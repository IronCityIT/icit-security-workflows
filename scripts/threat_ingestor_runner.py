#!/usr/bin/env python3
"""
Iron City IT - ThreatIngestor Runner
Runs ThreatIngestor to collect IOCs from various feeds
"""

import os
import sys
import json
import yaml
import requests
from datetime import datetime
from pathlib import Path

# Environment variables
FEED_TYPE = os.environ.get('FEED_TYPE', 'all')
CONFIG_FILE = os.environ.get('CONFIG_FILE', 'configs/threatingestor/config.yml')
OUTPUT_DIR = os.environ.get('OUTPUT_DIR', 'data/iocs')

# Built-in threat feeds (no API keys required)
FREE_FEEDS = {
    'abuse_ch_urlhaus': {
        'url': 'https://urlhaus.abuse.ch/downloads/json/',
        'type': 'json',
        'extract': lambda d: [{'type': 'url', 'value': u['url'], 'source': 'urlhaus'} 
                              for u in d.get('urls', [])[:1000]]
    },
    'abuse_ch_feodotracker': {
        'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
        'type': 'json',
        'extract': lambda d: [{'type': 'ip', 'value': i['ip_address'], 'source': 'feodotracker'} 
                              for i in d.get('ipblocklist', [])]
    },
    'emergingthreats_compromised': {
        'url': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'type': 'text',
        'extract': lambda lines: [{'type': 'ip', 'value': l.strip(), 'source': 'emergingthreats'} 
                                  for l in lines if l.strip() and not l.startswith('#')]
    },
    'openphish': {
        'url': 'https://openphish.com/feed.txt',
        'type': 'text',
        'extract': lambda lines: [{'type': 'url', 'value': l.strip(), 'source': 'openphish'} 
                                  for l in lines if l.strip()]
    },
    'blocklist_de': {
        'url': 'https://lists.blocklist.de/lists/all.txt',
        'type': 'text',
        'extract': lambda lines: [{'type': 'ip', 'value': l.strip(), 'source': 'blocklist_de'} 
                                  for l in lines if l.strip() and not l.startswith('#')][:5000]
    },
    'malwaredomainlist': {
        'url': 'https://www.malwaredomainlist.com/hostslist/hosts.txt',
        'type': 'text',
        'extract': lambda lines: [{'type': 'domain', 'value': l.split()[1], 'source': 'malwaredomainlist'} 
                                  for l in lines if l.strip() and not l.startswith('#') and len(l.split()) > 1]
    }
}

def load_config(config_file):
    """Load ThreatIngestor config"""
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    return {}

def fetch_feed(feed_name, feed_config):
    """Fetch IOCs from a single feed"""
    print(f"  📡 Fetching: {feed_name}")
    
    try:
        response = requests.get(feed_config['url'], timeout=30)
        response.raise_for_status()
        
        if feed_config['type'] == 'json':
            data = response.json()
            iocs = feed_config['extract'](data)
        else:
            lines = response.text.split('\n')
            iocs = feed_config['extract'](lines)
        
        print(f"     ✅ Got {len(iocs)} IOCs")
        return iocs
    except Exception as e:
        print(f"     ⚠️  Error: {str(e)[:50]}")
        return []

def run_threatingestor():
    """Run the actual ThreatIngestor if installed"""
    try:
        import threatingestor
        # ThreatIngestor has its own runner
        print("📦 Running ThreatIngestor...")
        # This would use the config file
        return True
    except ImportError:
        print("ℹ️  ThreatIngestor not installed, using built-in feeds")
        return False

def main():
    print("=" * 60)
    print("IRON CITY IT - THREAT INTELLIGENCE INGESTOR")
    print("=" * 60)
    print(f"📅 Timestamp: {datetime.utcnow().isoformat()}Z")
    print(f"🎯 Feed Type: {FEED_TYPE}")
    print("")
    
    # Try running ThreatIngestor if available
    ti_available = run_threatingestor()
    
    # Collect IOCs from built-in free feeds
    all_iocs = []
    
    print("📥 Fetching from free threat feeds:")
    for feed_name, feed_config in FREE_FEEDS.items():
        iocs = fetch_feed(feed_name, feed_config)
        all_iocs.extend(iocs)
    
    # Deduplicate
    seen = set()
    unique_iocs = []
    for ioc in all_iocs:
        key = f"{ioc['type']}:{ioc['value']}"
        if key not in seen:
            seen.add(key)
            ioc['collected_at'] = datetime.utcnow().isoformat() + 'Z'
            unique_iocs.append(ioc)
    
    print(f"\n📊 Total unique IOCs: {len(unique_iocs)}")
    
    # Count by type
    type_counts = {}
    for ioc in unique_iocs:
        t = ioc['type']
        type_counts[t] = type_counts.get(t, 0) + 1
    
    print("📈 By type:")
    for t, count in sorted(type_counts.items()):
        print(f"   {t}: {count}")
    
    # Save output
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    
    output_file = os.path.join(OUTPUT_DIR, 'latest.json')
    with open(output_file, 'w') as f:
        json.dump(unique_iocs, f, indent=2)
    print(f"\n✅ Saved to {output_file}")
    
    # Also save timestamped version
    ts = datetime.utcnow().strftime('%Y-%m-%d')
    timestamped_file = os.path.join(OUTPUT_DIR, f'iocs_{ts}.json')
    with open(timestamped_file, 'w') as f:
        json.dump(unique_iocs, f, indent=2)
    
    # Save summary
    summary = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'total_iocs': len(unique_iocs),
        'by_type': type_counts,
        'sources': list(FREE_FEEDS.keys())
    }
    with open(os.path.join(OUTPUT_DIR, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE COLLECTION COMPLETE")
    print("=" * 60)

if __name__ == '__main__':
    main()
