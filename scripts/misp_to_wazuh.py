#!/usr/bin/env python3
"""
Iron City IT - MISP to Wazuh IOC Sync
Syncs IOCs from MISP/ThreatIngestor to Wazuh CDB lists
"""

import os
import sys
import json
import requests
from datetime import datetime

# Environment variables
WAZUH_API_URL = os.environ.get('WAZUH_API_URL', '').rstrip('/')
WAZUH_API_USER = os.environ.get('WAZUH_API_USER', 'wazuh-wui')
WAZUH_API_PASS = os.environ.get('WAZUH_API_PASS', '')
IOC_FILE = os.environ.get('IOC_FILE', 'data/iocs/latest.json')
MISP_URL = os.environ.get('MISP_URL', '')
MISP_API_KEY = os.environ.get('MISP_API_KEY', '')

def get_wazuh_token():
    """Authenticate with Wazuh API and get token"""
    print("🔐 Authenticating with Wazuh API...")
    
    response = requests.post(
        f'{WAZUH_API_URL}/security/user/authenticate',
        auth=(WAZUH_API_USER, WAZUH_API_PASS),
        verify=False  # Adjust for production
    )
    
    if response.status_code == 200:
        token = response.json().get('data', {}).get('token')
        print("✅ Authenticated successfully")
        return token
    else:
        print(f"❌ Authentication failed: {response.status_code}")
        return None

def load_iocs(ioc_file):
    """Load IOCs from file"""
    print(f"📥 Loading IOCs from {ioc_file}...")
    
    if not os.path.exists(ioc_file):
        print(f"⚠️  IOC file not found: {ioc_file}")
        return []
    
    with open(ioc_file, 'r') as f:
        iocs = json.load(f)
    
    print(f"✅ Loaded {len(iocs)} IOCs")
    return iocs

def fetch_misp_iocs():
    """Fetch IOCs directly from MISP if configured"""
    if not MISP_URL or not MISP_API_KEY:
        return []
    
    print(f"📡 Fetching IOCs from MISP...")
    
    headers = {
        'Authorization': MISP_API_KEY,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    # Get recent attributes (last 24 hours)
    response = requests.post(
        f'{MISP_URL}/attributes/restSearch',
        headers=headers,
        json={
            'returnFormat': 'json',
            'type': ['ip-src', 'ip-dst', 'domain', 'url', 'md5', 'sha1', 'sha256'],
            'to_ids': True,
            'publish_timestamp': '1d'
        },
        verify=False
    )
    
    if response.status_code == 200:
        attributes = response.json().get('response', {}).get('Attribute', [])
        iocs = []
        for attr in attributes:
            iocs.append({
                'type': attr.get('type'),
                'value': attr.get('value'),
                'source': 'misp',
                'timestamp': attr.get('timestamp')
            })
        print(f"✅ Fetched {len(iocs)} IOCs from MISP")
        return iocs
    else:
        print(f"⚠️  MISP fetch failed: {response.status_code}")
        return []

def format_cdb_list(iocs, ioc_type):
    """Format IOCs for Wazuh CDB list"""
    filtered = [ioc['value'] for ioc in iocs if ioc.get('type') == ioc_type]
    # CDB format: key:value (we use key: for simple lookup)
    return '\n'.join([f'{value}:' for value in set(filtered)])

def update_wazuh_cdb(token, list_name, content):
    """Update a Wazuh CDB list"""
    print(f"📤 Updating Wazuh CDB list: {list_name}")
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/octet-stream'
    }
    
    response = requests.put(
        f'{WAZUH_API_URL}/lists/files/{list_name}',
        headers=headers,
        params={'overwrite': 'true'},
        data=content.encode(),
        verify=False
    )
    
    if response.status_code == 200:
        print(f"✅ Updated {list_name}")
        return True
    else:
        print(f"⚠️  Failed to update {list_name}: {response.status_code}")
        return False

def main():
    print("=" * 60)
    print("IRON CITY IT - MISP TO WAZUH IOC SYNC")
    print("=" * 60)
    
    # Load IOCs from file
    iocs = load_iocs(IOC_FILE)
    
    # Also fetch from MISP if configured
    misp_iocs = fetch_misp_iocs()
    iocs.extend(misp_iocs)
    
    if not iocs:
        print("⚠️  No IOCs to sync")
        sys.exit(0)
    
    # Group IOCs by type
    type_counts = {}
    for ioc in iocs:
        t = ioc.get('type', 'unknown')
        type_counts[t] = type_counts.get(t, 0) + 1
    
    print("\n📊 IOC Summary:")
    for t, count in sorted(type_counts.items()):
        print(f"   {t}: {count}")
    
    # If Wazuh API is configured, push to CDB lists
    if WAZUH_API_URL and WAZUH_API_PASS:
        token = get_wazuh_token()
        if token:
            # Create CDB lists for different IOC types
            type_mappings = {
                'ip-src': 'threat-intel-ips',
                'ip-dst': 'threat-intel-ips',
                'ip': 'threat-intel-ips',
                'domain': 'threat-intel-domains',
                'url': 'threat-intel-urls',
                'md5': 'threat-intel-hashes',
                'sha1': 'threat-intel-hashes',
                'sha256': 'threat-intel-hashes'
            }
            
            # Group by target list
            lists = {}
            for ioc in iocs:
                ioc_type = ioc.get('type', '')
                list_name = type_mappings.get(ioc_type)
                if list_name:
                    if list_name not in lists:
                        lists[list_name] = []
                    lists[list_name].append(ioc['value'])
            
            # Update each CDB list
            for list_name, values in lists.items():
                content = '\n'.join([f'{v}:' for v in set(values)])
                update_wazuh_cdb(token, list_name, content)
    else:
        print("\nℹ️  Wazuh API not configured - saving locally only")
    
    # Save combined IOCs locally
    os.makedirs('data/iocs', exist_ok=True)
    output_file = 'data/iocs/combined.json'
    with open(output_file, 'w') as f:
        json.dump(iocs, f, indent=2)
    print(f"✅ Saved {len(iocs)} IOCs to {output_file}")
    
    # Save as simple text lists for manual use
    for ioc_type in ['ip', 'ip-src', 'ip-dst', 'domain', 'url']:
        values = [ioc['value'] for ioc in iocs if ioc.get('type') == ioc_type]
        if values:
            with open(f'data/iocs/{ioc_type.replace("-", "_")}_list.txt', 'w') as f:
                f.write('\n'.join(set(values)))
    
    print("\n" + "=" * 60)
    print("IOC SYNC COMPLETE")
    print("=" * 60)

if __name__ == '__main__':
    main()
