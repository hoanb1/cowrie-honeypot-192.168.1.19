#!/usr/bin/env python3
"""
GeoIP Module for Cowrie Dashboard
Author: AI Assistant
Description: Add geographic location support to Cowrie monitoring
"""

import geoip2.database
import geoip2.errors
import json
import os
from datetime import datetime

class GeoIPService:
    def __init__(self, db_path='/home/cowrie/cowrie/GeoLite2-City.mmdb'):
        self.db_path = db_path
        self.reader = None
        self.load_database()
    
    def load_database(self):
        """Load GeoIP database"""
        try:
            if os.path.exists(self.db_path):
                self.reader = geoip2.database.Reader(self.db_path)
                print(f"GeoIP database loaded: {self.db_path}")
            else:
                print(f"GeoIP database not found: {self.db_path}")
                self.reader = None
        except Exception as e:
            print(f"Error loading GeoIP database: {e}")
            self.reader = None
    
    def get_location(self, ip_address):
        """Get geographic location for IP address"""
        if not self.reader:
            return None
        
        try:
            response = self.reader.city(ip_address)
            
            return {
                'ip': ip_address,
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone,
                'accuracy': response.location.accuracy_radius
            }
        except geoip2.errors.AddressNotFoundError:
            return {
                'ip': ip_address,
                'country': 'Unknown',
                'country_code': 'XX',
                'city': 'Unknown',
                'latitude': 0,
                'longitude': 0,
                'timezone': 'Unknown',
                'accuracy': 0
            }
        except Exception as e:
            print(f"Error getting location for {ip_address}: {e}")
            return None
    
    def enrich_log_entry(self, log_entry):
        """Add geographic information to log entry"""
        if 'src_ip' in log_entry:
            location = self.get_location(log_entry['src_ip'])
            if location:
                log_entry['geo_location'] = location
        return log_entry
    
    def get_attack_statistics_by_country(self, log_entries):
        """Get attack statistics grouped by country"""
        country_stats = {}
        
        for entry in log_entries:
            if 'geo_location' in entry:
                country = entry['geo_location']['country']
                country_code = entry['geo_location']['country_code']
                
                if country not in country_stats:
                    country_stats[country] = {
                        'country_code': country_code,
                        'count': 0,
                        'ips': set(),
                        'coordinates': []
                    }
                
                country_stats[country]['count'] += 1
                country_stats[country]['ips'].add(entry['src_ip'])
                
                if entry['geo_location']['latitude'] and entry['geo_location']['longitude']:
                    country_stats[country]['coordinates'].append({
                        'lat': entry['geo_location']['latitude'],
                        'lng': entry['geo_location']['longitude'],
                        'ip': entry['src_ip'],
                        'timestamp': entry.get('timestamp'),
                        'event': entry.get('eventid')
                    })
        
        # Convert sets to lists for JSON serialization
        for country in country_stats:
            country_stats[country]['ips'] = list(country_stats[country]['ips'])
        
        return country_stats
    
    def get_top_attacking_countries(self, log_entries, limit=10):
        """Get top attacking countries"""
        country_stats = self.get_attack_statistics_by_country(log_entries)
        
        # Sort by count and return top N
        sorted_countries = sorted(
            country_stats.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )
        
        return dict(sorted_countries[:limit])
    
    def get_map_data(self, log_entries):
        """Get data formatted for map visualization"""
        map_data = {
            'markers': [],
            'heatpoints': []
        }
        
        for entry in log_entries:
            if 'geo_location' in entry and entry['geo_location']['latitude'] and entry['geo_location']['longitude']:
                location = entry['geo_location']
                
                # Add marker for individual attacks
                map_data['markers'].append({
                    'lat': location['latitude'],
                    'lng': location['longitude'],
                    'ip': entry['src_ip'],
                    'country': location['country'],
                    'city': location['city'],
                    'timestamp': entry.get('timestamp'),
                    'event': entry.get('eventid'),
                    'password': entry.get('password')
                })
                
                # Add heatpoint for intensity
                map_data['heatpoints'].append({
                    'lat': location['latitude'],
                    'lng': location['longitude'],
                    'intensity': 1
                })
        
        return map_data
    
    def close(self):
        """Close GeoIP database connection"""
        if self.reader:
            self.reader.close()

# Test function
def test_geoip():
    """Test GeoIP functionality"""
    geoip = GeoIPService()
    
    # Test with some known IPs
    test_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
    
    for ip in test_ips:
        location = geoip.get_location(ip)
        print(f"IP: {ip}")
        if location:
            print(f"  Country: {location['country']} ({location['country_code']})")
            print(f"  City: {location['city']}")
            print(f"  Coordinates: {location['latitude']}, {location['longitude']}")
        else:
            print("  Location not found")
        print()
    
    geoip.close()

if __name__ == "__main__":
    test_geoip()
