#!/usr/bin/env python3
"""
Iron City IT - DefectDojo Import Script
Imports scan results from various security tools into DefectDojo
"""

import os
import sys
import json
import requests
from datetime import datetime

# Environment variables
DEFECTDOJO_URL = os.environ.get('DEFECTDOJO_URL', '').rstrip('/')
DEFECTDOJO_API_KEY = os.environ.get('DEFECTDOJO_API_KEY', '')
SCAN_TYPE = os.environ.get('SCAN_TYPE', 'zap')
SCAN_FILE = os.environ.get('SCAN_FILE', '')
CLIENT_ID = os.environ.get('CLIENT_ID', 'unknown')
ENGAGEMENT_NAME = os.environ.get('ENGAGEMENT_NAME', 'Security Assessment')

# Scan type mapping to DefectDojo scan types
SCAN_TYPE_MAP = {
    'zap': 'ZAP Scan',
    'nuclei': 'Nuclei Scan',
    'nmap': 'Nmap Scan',
    'qualys': 'Qualys Scan',
    'nessus': 'Nessus Scan',
    'burp': 'Burp Scan',
    'openvas': 'OpenVAS CSV',
    'trivy': 'Trivy Scan',
    'semgrep': 'Semgrep JSON Report',
}

def get_headers():
    return {
        'Authorization': f'Token {DEFECTDOJO_API_KEY}',
        'Accept': 'application/json'
    }

def find_or_create_product(client_id):
    """Find or create a product for the client"""
    print(f"🔍 Looking for product: {client_id}")
    
    response = requests.get(
        f'{DEFECTDOJO_URL}/api/v2/products/',
        headers=get_headers(),
        params={'name': client_id}
    )
    
    if response.status_code == 200:
        products = response.json().get('results', [])
        if products:
            print(f"✅ Found existing product: {products[0]['id']}")
            return products[0]['id']
    
    print(f"📦 Creating new product: {client_id}")
    response = requests.post(
        f'{DEFECTDOJO_URL}/api/v2/products/',
        headers={**get_headers(), 'Content-Type': 'application/json'},
        json={
            'name': client_id,
            'description': f'Security assessments for {client_id}',
            'prod_type': 1
        }
    )
    
    if response.status_code == 201:
        product_id = response.json()['id']
        print(f"✅ Created product: {product_id}")
        return product_id
    else:
        print(f"❌ Failed to create product: {response.text}")
        sys.exit(1)

def find_or_create_engagement(product_id, engagement_name):
    """Find or create an engagement"""
    print(f"🔍 Looking for engagement: {engagement_name}")
    
    response = requests.get(
        f'{DEFECTDOJO_URL}/api/v2/engagements/',
        headers=get_headers(),
        params={'product': product_id, 'name': engagement_name}
    )
    
    if response.status_code == 200:
        engagements = response.json().get('results', [])
        if engagements:
            print(f"✅ Found existing engagement: {engagements[0]['id']}")
            return engagements[0]['id']
    
    print(f"📋 Creating new engagement: {engagement_name}")
    today = datetime.now().strftime('%Y-%m-%d')
    
    response = requests.post(
        f'{DEFECTDOJO_URL}/api/v2/engagements/',
        headers={**get_headers(), 'Content-Type': 'application/json'},
        json={
            'name': engagement_name,
            'product': product_id,
            'target_start': today,
            'target_end': today,
            'engagement_type': 'CI/CD',
            'status': 'In Progress'
        }
    )
    
    if response.status_code == 201:
        engagement_id = response.json()['id']
        print(f"✅ Created engagement: {engagement_id}")
        return engagement_id
    else:
        print(f"❌ Failed to create engagement: {response.text}")
        sys.exit(1)

def import_scan(engagement_id, scan_file, scan_type):
    """Import scan results into DefectDojo"""
    print(f"📤 Importing {scan_type} scan...")
    
    dd_scan_type = SCAN_TYPE_MAP.get(scan_type, 'Generic Findings Import')
    
    with open(scan_file, 'rb') as f:
        response = requests.post(
            f'{DEFECTDOJO_URL}/api/v2/import-scan/',
            headers={'Authorization': f'Token {DEFECTDOJO_API_KEY}'},
            data={
                'engagement': engagement_id,
                'scan_type': dd_scan_type,
                'active': True,
                'verified': False,
                'close_old_findings': False,
                'push_to_jira': False
            },
            files={'file': f}
        )
    
    if response.status_code in [200, 201]:
        result = response.json()
        print(f"✅ Import successful!")
        print(f"   - Test ID: {result.get('test', 'N/A')}")
        print(f"   - Findings created: {result.get('statistics', {}).get('created', 0)}")
        return result
    else:
        print(f"❌ Import failed: {response.status_code}")
        print(response.text)
        sys.exit(1)

def main():
    print("=" * 60)
    print("IRON CITY IT - DEFECTDOJO IMPORT")
    print("=" * 60)
    
    if not DEFECTDOJO_URL:
        print("❌ DEFECTDOJO_URL not set")
        print("ℹ️  Add DEFECTDOJO_URL to repository secrets")
        sys.exit(0)
    
    if not DEFECTDOJO_API_KEY:
        print("❌ DEFECTDOJO_API_KEY not set")
        sys.exit(0)
    
    if not os.path.exists(SCAN_FILE):
        print(f"❌ Scan file not found: {SCAN_FILE}")
        sys.exit(1)
    
    print(f"📁 Scan File: {SCAN_FILE}")
    print(f"🔧 Scan Type: {SCAN_TYPE}")
    print(f"🏢 Client: {CLIENT_ID}")
    print("")
    
    product_id = find_or_create_product(CLIENT_ID)
    engagement_id = find_or_create_engagement(product_id, ENGAGEMENT_NAME)
    import_scan(engagement_id, SCAN_FILE, SCAN_TYPE)
    
    print("")
    print("IMPORT COMPLETE")

if __name__ == '__main__':
    main()
