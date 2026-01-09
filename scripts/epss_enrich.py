#!/usr/bin/env python3
"""
Iron City IT - EPSS Vulnerability Enrichment Script
Enriches vulnerability data with EPSS (Exploit Prediction Scoring System) scores
"""

import os
import sys
import json
import csv
from datetime import datetime

EPSS_FILE = os.environ.get('EPSS_FILE', 'data/epss/epss_scores_latest.csv')
VULN_FILE = os.environ.get('VULN_FILE', '')  # Optional: enrich existing vuln file
OUTPUT_DIR = os.environ.get('OUTPUT_DIR', 'data/enriched')

def load_epss_scores(epss_file):
    """Load EPSS scores into a dictionary keyed by CVE ID"""
    print(f"📥 Loading EPSS scores from {epss_file}...")
    
    scores = {}
    with open(epss_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve = row.get('cve', '').strip()
            epss = row.get('epss', '0')
            percentile = row.get('percentile', '0')
            
            if cve.startswith('CVE-'):
                scores[cve] = {
                    'epss_score': float(epss),
                    'epss_percentile': float(percentile)
                }
    
    print(f"✅ Loaded {len(scores)} EPSS scores")
    return scores

def get_risk_level(epss_score):
    """Convert EPSS score to risk level"""
    if epss_score >= 0.7:
        return 'CRITICAL'
    elif epss_score >= 0.4:
        return 'HIGH'
    elif epss_score >= 0.1:
        return 'MEDIUM'
    else:
        return 'LOW'

def analyze_epss_data(scores):
    """Generate analysis of EPSS data"""
    print("\n📊 EPSS Analysis")
    print("=" * 50)
    
    # Count by risk level
    critical = sum(1 for s in scores.values() if s['epss_score'] >= 0.7)
    high = sum(1 for s in scores.values() if 0.4 <= s['epss_score'] < 0.7)
    medium = sum(1 for s in scores.values() if 0.1 <= s['epss_score'] < 0.4)
    low = sum(1 for s in scores.values() if s['epss_score'] < 0.1)
    
    print(f"🔴 Critical (≥70%): {critical:,}")
    print(f"🟠 High (40-70%):   {high:,}")
    print(f"🟡 Medium (10-40%): {medium:,}")
    print(f"🟢 Low (<10%):      {low:,}")
    print(f"📊 Total CVEs:      {len(scores):,}")
    
    # Top 10 most likely to be exploited
    print("\n🔥 Top 10 Most Likely to be Exploited:")
    print("-" * 50)
    
    sorted_scores = sorted(scores.items(), key=lambda x: x[1]['epss_score'], reverse=True)
    for cve, data in sorted_scores[:10]:
        pct = data['epss_score'] * 100
        print(f"  {cve}: {pct:.2f}% probability")
    
    return {
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'total': len(scores),
        'top_10': [{'cve': cve, 'epss': data['epss_score']} for cve, data in sorted_scores[:10]]
    }

def enrich_vulnerabilities(vuln_file, scores):
    """Enrich a vulnerability file with EPSS scores"""
    print(f"\n📤 Enriching vulnerabilities from {vuln_file}...")
    
    with open(vuln_file, 'r') as f:
        vulns = json.load(f)
    
    enriched = 0
    for vuln in vulns:
        cve = vuln.get('cve', vuln.get('cve_id', ''))
        if cve in scores:
            vuln['epss_score'] = scores[cve]['epss_score']
            vuln['epss_percentile'] = scores[cve]['epss_percentile']
            vuln['epss_risk_level'] = get_risk_level(scores[cve]['epss_score'])
            enriched += 1
    
    print(f"✅ Enriched {enriched}/{len(vulns)} vulnerabilities")
    
    # Sort by EPSS score (highest first)
    vulns.sort(key=lambda x: x.get('epss_score', 0), reverse=True)
    
    return vulns

def save_prioritized_list(scores, output_dir):
    """Save a prioritized list of CVEs for quick reference"""
    os.makedirs(output_dir, exist_ok=True)
    
    # High-risk CVEs (EPSS >= 10%)
    high_risk = {cve: data for cve, data in scores.items() if data['epss_score'] >= 0.1}
    
    output_file = os.path.join(output_dir, 'high_risk_cves.json')
    with open(output_file, 'w') as f:
        json.dump(high_risk, f, indent=2)
    
    print(f"✅ Saved {len(high_risk)} high-risk CVEs to {output_file}")
    
    # Critical CVEs (EPSS >= 70%)
    critical = {cve: data for cve, data in scores.items() if data['epss_score'] >= 0.7}
    
    output_file = os.path.join(output_dir, 'critical_cves.json')
    with open(output_file, 'w') as f:
        json.dump(critical, f, indent=2)
    
    print(f"✅ Saved {len(critical)} critical CVEs to {output_file}")

def main():
    print("=" * 60)
    print("IRON CITY IT - EPSS VULNERABILITY ENRICHMENT")
    print("=" * 60)
    
    if not os.path.exists(EPSS_FILE):
        print(f"❌ EPSS file not found: {EPSS_FILE}")
        print("ℹ️  Run the epss-update workflow first")
        sys.exit(1)
    
    # Load EPSS scores
    scores = load_epss_scores(EPSS_FILE)
    
    # Analyze the data
    analysis = analyze_epss_data(scores)
    
    # Save analysis
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, 'epss_analysis.json'), 'w') as f:
        json.dump({
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'analysis': analysis
        }, f, indent=2)
    
    # Save prioritized lists
    save_prioritized_list(scores, OUTPUT_DIR)
    
    # Enrich vulnerability file if provided
    if VULN_FILE and os.path.exists(VULN_FILE):
        enriched = enrich_vulnerabilities(VULN_FILE, scores)
        output_file = os.path.join(OUTPUT_DIR, 'enriched_vulns.json')
        with open(output_file, 'w') as f:
            json.dump(enriched, f, indent=2)
        print(f"✅ Saved enriched vulnerabilities to {output_file}")
    
    print("\n" + "=" * 60)
    print("EPSS ENRICHMENT COMPLETE")
    print("=" * 60)

if __name__ == '__main__':
    main()
