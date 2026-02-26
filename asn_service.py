import geoip2.database
import geoip2.errors

class ASNService:
    def __init__(self, db_path=None):
        # Use dedicated ASN database for organization info
        self.db_path = db_path or '/home/cowrie/cowrie-dashboard/data/GeoLite2-ASN.mmdb'
        try:
            self.reader = geoip2.database.Reader(self.db_path)
            print(f"✅ ASN database loaded: {self.db_path}")
        except Exception as e:
            print(f"❌ Error loading ASN database: {e}")
            # Fallback to GeoLite2-City database
            self.db_path = '/home/cowrie/cowrie-dashboard/data/GeoLite2-City.mmdb'
            try:
                self.reader = geoip2.database.Reader(self.db_path)
                print(f"✅ Fallback to GeoIP database: {self.db_path}")
            except Exception as e2:
                print(f"❌ Error loading fallback database: {e2}")
                self.reader = None
    
    def get_asn_info(self, ip):
        if not self.reader:
            return {
                'asn': 'Unknown',
                'organization': 'Unknown'
            }
        
        try:
            # Use asn method for ASN database, fallback to city for GeoIP database
            if 'ASN' in self.db_path:
                response = self.reader.asn(ip)
                org = response.autonomous_system_organization
                asn = f"AS{response.autonomous_system_number}"
            else:
                response = self.reader.city(ip)
                # Extract organization from various fields
                org = None
                if hasattr(response, 'traits') and hasattr(response.traits, 'autonomous_system_organization'):
                    org = response.traits.autonomous_system_organization
                elif hasattr(response, 'traits') and hasattr(response.traits, 'isp'):
                    org = response.traits.isp
                elif hasattr(response, 'traits') and hasattr(response.traits, 'organization'):
                    org = response.traits.organization
                
                # Get ASN if available
                asn = 'Unknown'
                if hasattr(response, 'traits') and hasattr(response.traits, 'autonomous_system_number'):
                    asn = f"AS{response.traits.autonomous_system_number}"
            
            return {
                'asn': asn,
                'organization': org or 'Unknown'
            }
        except (geoip2.errors.AddressNotFoundError, geoip2.errors.GeoIP2Error) as e:
            print(f"⚠️ ASN lookup failed for {ip}: {e}")
            return {
                'asn': 'Unknown',
                'organization': 'Unknown'
            }
    
    def enrich_log_entry(self, entry):
        entry['asn_info'] = self.get_asn_info(entry.get('src_ip', ''))
        return entry
    
    def close(self):
        if self.reader:
            self.reader.close()
