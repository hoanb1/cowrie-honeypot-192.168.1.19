#!/usr/bin/env python3
"""
ASN and Organization Lookup Service for Cowrie Dashboard
Author: AI Assistant
Description: Add ASN and organization information to IP addresses
"""

import whois
import requests
import json
import time
import re
from datetime import datetime
import socket

class ASNService:
    def __init__(self):
        self.cache = {}
        self.whois_cache = {}
        self.rate_limit_delay = 1  # Delay between requests to avoid rate limiting
        
    def get_asn_info(self, ip_address):
        """Get ASN and organization information for IP address"""
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        try:
            # Try multiple methods to get ASN info
            
            # Method 1: WHOIS lookup
            asn_info = self.get_whois_info(ip_address)
            
            # Method 2: IPInfo API (free tier)
            if not asn_info or not asn_info.get('organization'):
                asn_info = self.get_ipinfo_info(ip_address)
            
            # Method 3: IP-API (free)
            if not asn_info or not asn_info.get('organization'):
                asn_info = self.get_ip_api_info(ip_address)
            
            # Cache the result
            if asn_info:
                self.cache[ip_address] = asn_info
            
            time.sleep(self.rate_limit_delay)  # Rate limiting
            
            return asn_info
            
        except Exception as e:
            print(f"Error getting ASN info for {ip_address}: {e}")
            return self.get_default_info(ip_address)
    
    def get_whois_info(self, ip_address):
        """Get WHOIS information for IP"""
        try:
            if ip_address in self.whois_cache:
                return self.whois_cache[ip_address]
            
            w = whois.whois(ip_address)
            
            if w:
                info = {
                    'ip': ip_address,
                    'asn': self.extract_asn(w.text or ''),
                    'organization': self.clean_organization(w.org_name or w.organization or ''),
                    'country': w.country,
                    'range': w.cidr or w.netrange,
                    'updated': w.updated_date,
                    'source': 'whois'
                }
                
                self.whois_cache[ip_address] = info
                return info
                
        except Exception as e:
            print(f"WHOIS lookup failed for {ip_address}: {e}")
        
        return None
    
    def get_ipinfo_info(self, ip_address):
        """Get IP information from ipinfo.io API"""
        try:
            url = f"https://ipinfo.io/{ip_address}/json"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip_address,
                    'asn': data.get('org', '').split(' ')[0] if data.get('org') else None,
                    'organization': ' '.join(data.get('org', '').split(' ')[1:]) if data.get('org') else None,
                    'country': data.get('country'),
                    'range': None,
                    'updated': None,
                    'source': 'ipinfo'
                }
        except Exception as e:
            print(f"IPInfo lookup failed for {ip_address}: {e}")
        
        return None
    
    def get_ip_api_info(self, ip_address):
        """Get IP information from ip-api.com API"""
        try:
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'ip': ip_address,
                        'asn': data.get('as', '').split(' ')[0] if data.get('as') else None,
                        'organization': ' '.join(data.get('as', '').split(' ')[1:]) if data.get('as') else None,
                        'country': data.get('countryCode'),
                        'range': None,
                        'updated': None,
                        'source': 'ipapi'
                    }
        except Exception as e:
            print(f"IP-API lookup failed for {ip_address}: {e}")
        
        return None
    
    def extract_asn(self, whois_text):
        """Extract ASN from WHOIS text"""
        asn_patterns = [
            r'ASN:\s*(AS\d+)',
            r'Autonomous System Number\s*(AS\d+)',
            r'origin:\s*(AS\d+)',
            r'OriginAS:\s*(AS\d+)',
            r'(AS\d+)',
        ]
        
        for pattern in asn_patterns:
            match = re.search(pattern, whois_text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def clean_organization(self, org):
        """Clean organization name"""
        if not org:
            return None
        
        # Remove common prefixes/suffixes
        org = re.sub(r'^(ASN|AS)\d+\s*', '', org, flags=re.IGNORECASE)
        org = re.sub(r'\b(LTD|INC|CORP|LLC|GmbH|AG|SA|S\.A\.)\b\.?', '', org, flags=re.IGNORECASE)
        org = re.sub(r'\s+', ' ', org).strip()
        
        return org if org else None
    
    def get_default_info(self, ip_address):
        """Get default info when all methods fail"""
        return {
            'ip': ip_address,
            'asn': None,
            'organization': None,
            'country': None,
            'range': None,
            'updated': None,
            'source': 'default'
        }
    
    def get_top_organizations(self, ip_list, limit=10):
        """Get top organizations from a list of IPs"""
        org_stats = {}
        
        for ip in ip_list:
            asn_info = self.get_asn_info(ip)
            if asn_info and asn_info.get('organization'):
                org = asn_info['organization']
                if org not in org_stats:
                    org_stats[org] = {
                        'count': 0,
                        'ips': [],
                        'asn': asn_info['asn'],
                        'country': asn_info['country']
                    }
                
                org_stats[org]['count'] += 1
                org_stats[org]['ips'].append(ip)
        
        # Sort by count and return top N
        sorted_orgs = sorted(org_stats.items(), key=lambda x: x[1]['count'], reverse=True)
        return dict(sorted_orgs[:limit])
    
    def get_top_asns(self, ip_list, limit=10):
        """Get top ASNs from a list of IPs"""
        asn_stats = {}
        
        for ip in ip_list:
            asn_info = self.get_asn_info(ip)
            if asn_info and asn_info.get('asn'):
                asn = asn_info['asn']
                if asn not in asn_stats:
                    asn_stats[asn] = {
                        'count': 0,
                        'ips': [],
                        'organization': asn_info['organization'],
                        'country': asn_info['country']
                    }
                
                asn_stats[asn]['count'] += 1
                asn_stats[asn]['ips'].append(ip)
        
        # Sort by count and return top N
        sorted_asns = sorted(asn_stats.items(), key=lambda x: x[1]['count'], reverse=True)
        return dict(sorted_asns[:limit])
    
    def enrich_log_entry(self, log_entry):
        """Add ASN and organization information to log entry"""
        if 'src_ip' in log_entry:
            asn_info = self.get_asn_info(log_entry['src_ip'])
            if asn_info:
                log_entry['asn_info'] = asn_info
        return log_entry
    
    def get_organization_stats(self, log_entries):
        """Get organization statistics from log entries"""
        org_stats = {}
        
        for entry in log_entries:
            if 'asn_info' in entry and entry['asn_info'].get('organization'):
                org = entry['asn_info']['organization']
                if org not in org_stats:
                    org_stats[org] = {
                        'count': 0,
                        'ips': set(),
                        'asn': entry['asn_info']['asn'],
                        'country': entry['asn_info']['country'],
                        'events': defaultdict(int)
                    }
                
                org_stats[org]['count'] += 1
                org_stats[org]['ips'].add(entry['src_ip'])
                org_stats[org]['events'][entry.get('eventid', 'unknown')] += 1
        
        # Convert sets to lists for JSON serialization
        for org in org_stats:
            org_stats[org]['ips'] = list(org_stats[org]['ips'])
            org_stats[org]['events'] = dict(org_stats[org]['events'])
        
        return org_stats

# Test function
def test_asn_service():
    """Test ASN service functionality"""
    asn_service = ASNService()
    
    # Test with some known IPs
    test_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '183.81.33.183']
    
    for ip in test_ips:
        print(f"\n=== {ip} ===")
        asn_info = asn_service.get_asn_info(ip)
        if asn_info:
            print(f"ASN: {asn_info['asn']}")
            print(f"Organization: {asn_info['organization']}")
            print(f"Country: {asn_info['country']}")
            print(f"Source: {asn_info['source']}")
        else:
            print("No information found")

if __name__ == "__main__":
    test_asn_service()
