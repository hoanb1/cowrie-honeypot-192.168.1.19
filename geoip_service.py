import geoip2.database
import geoip2.errors

class GeoIPService:
    def __init__(self, db_path=None):
        self.db_path = db_path or '/home/cowrie/cowrie-dashboard/data/GeoLite2-City.mmdb'
        try:
            self.reader = geoip2.database.Reader(self.db_path)
            print(f"✅ GeoIP database loaded: {self.db_path}")
        except Exception as e:
            print(f"❌ Error loading GeoIP database: {e}")
            self.reader = None
    
    def get_location(self, ip):
        if not self.reader:
            return {
                'latitude': 37.751,
                'longitude': -97.822,
                'country': 'Unknown',
                'city': 'Unknown'
            }
        
        try:
            response = self.reader.city(ip)
            return {
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'country': response.country.name or 'Unknown',
                'city': response.city.name or 'Unknown'
            }
        except (geoip2.errors.AddressNotFoundError, geoip2.errors.GeoIP2Error) as e:
            print(f"⚠️ GeoIP lookup failed for {ip}: {e}")
            return {
                'latitude': 37.751,
                'longitude': -97.822,
                'country': 'Unknown',
                'city': 'Unknown'
            }
    
    def enrich_log_entry(self, entry):
        entry['geo_location'] = self.get_location(entry.get('src_ip', ''))
        return entry
    
    def close(self):
        if self.reader:
            self.reader.close()
