#!/usr/bin/env python3
"""
Cowrie Real-time Dashboard with GeoIP and ASN Support
Real-time monitoring with geographic and organization attack visualization
"""

# CRITICAL: eventlet monkey_patch MUST be called before any other imports
import eventlet
eventlet.monkey_patch()

import functools
import json
import logging
import os
import queue
import secrets
import signal
import sys
import time
import threading
from collections import deque, defaultdict
from datetime import datetime
from typing import Dict, Any, Optional
import gzip
import glob

from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO, emit

# Add services to path
sys.path.append('/home/cowrie/cowrie')

# Mock services for standalone operation (since geoip_service import may fail)
class GeoIPService:
    def __init__(self, db_path=None):
        self.db_path = db_path
        
        # Mock IP to country mapping for common attack sources
        self.ip_country_map = {
            '192.168.1.': 'Vietnam',
            '192.168.0.': 'Vietnam', 
            '10.0.0.': 'Local Network',
            '172.16.': 'Local Network',
            '172.17.': 'Local Network',
            '172.18.': 'Local Network',
            '172.19.': 'Local Network',
            '172.20.': 'Local Network',
            '172.21.': 'Local Network',
            '172.22.': 'Local Network',
            '172.23.': 'Local Network',
            '172.24.': 'Local Network',
            '172.25.': 'Local Network',
            '172.26.': 'Local Network',
            '172.27.': 'Local Network',
            '172.28.': 'Local Network',
            '172.29.': 'Local Network',
            '172.30.': 'Local Network',
            '172.31.': 'Local Network',
            '127.0.0.': 'Localhost',
            '203.113.': 'Vietnam',
            '118.68.': 'Vietnam',
            '171.224.': 'Vietnam',
            '171.225.': 'Vietnam',
            '171.226.': 'Vietnam',
            '171.227.': 'Vietnam',
            '171.228.': 'Vietnam',
            '171.229.': 'Vietnam',
            '171.230.': 'Vietnam',
            '171.231.': 'Vietnam',
            '183.80.': 'Vietnam',
            '183.81.': 'Vietnam'
        }
        
        # Country coordinates for mapping
        self.country_coords = {
            'Vietnam': {'lat': 14.0583, 'lng': 108.2772},
            'China': {'lat': 35.8617, 'lng': 104.1954},
            'United States': {'lat': 37.0902, 'lng': -95.7129},
            'Russia': {'lat': 61.5240, 'lng': 105.3188},
            'India': {'lat': 20.5937, 'lng': 78.9629},
            'Brazil': {'lat': -14.2350, 'lng': -51.9253},
            'Japan': {'lat': 36.2048, 'lng': 138.2529},
            'Germany': {'lat': 51.1657, 'lng': 10.4515},
            'United Kingdom': {'lat': 55.3781, 'lng': -3.4360},
            'France': {'lat': 46.2276, 'lng': 2.2137},
            'South Korea': {'lat': 35.9078, 'lng': 127.7669},
            'Italy': {'lat': 41.8719, 'lng': 12.5674},
            'Canada': {'lat': 56.1304, 'lng': -106.3468},
            'Australia': {'lat': -25.2744, 'lng': 133.7751},
            'Spain': {'lat': 40.4637, 'lng': -3.7492},
            'Netherlands': {'lat': 52.1326, 'lng': 5.2913},
            'Turkey': {'lat': 38.9637, 'lng': 35.2433},
            'Poland': {'lat': 51.9194, 'lng': 19.1451},
            'Thailand': {'lat': 15.8700, 'lng': 100.9925},
            'Indonesia': {'lat': -0.7893, 'lng': 113.9213},
            'Local Network': {'lat': 0, 'lng': 0},
            'Localhost': {'lat': 0, 'lng': 0}
        }
    
    def get_location(self, ip):
        if not ip:
            return {
                'latitude': 0,
                'longitude': 0,
                'country': 'Unknown',
                'city': 'Unknown'
            }
        
        # Check for known IP prefixes
        for prefix, country in self.ip_country_map.items():
            if ip.startswith(prefix):
                coords = self.country_coords.get(country, {'lat': 0, 'lng': 0})
                return {
                    'latitude': coords['lat'],
                    'longitude': coords['lng'],
                    'country': country,
                    'city': 'Unknown'
                }
        
        # For unknown IPs, simulate different countries based on IP hash
        # This creates variety in demo data
        import random
        random.seed(ip)  # Deterministic based on IP
        countries = ['China', 'United States', 'Russia', 'India', 'Brazil', 'Japan', 'Germany', 'United Kingdom', 'France']
        country = random.choice(countries)
        coords = self.country_coords.get(country, {'lat': 0, 'lng': 0})
        
        return {
            'latitude': coords['lat'],
            'longitude': coords['lng'],
            'country': country,
            'city': 'Unknown'
        }
    
    def enrich_log_entry(self, entry):
        entry['geo_location'] = self.get_location(entry.get('src_ip', ''))
        return entry
    
    def close(self):
        pass

class ASNService:
    def __init__(self, db_path=None):
        self.db_path = db_path
    
    def get_asn_info(self, ip):
        return {
            'asn': 'Unknown',
            'organization': 'Unknown'
        }
    
    def enrich_log_entry(self, entry):
        entry['asn_info'] = self.get_asn_info(entry.get('src_ip', ''))
        return entry
    
    def close(self):
        pass

class BoundedCounter:
    def __init__(self, max_size=1000):
        self.max_size = max_size
        self.counts = {}
    
    def increment(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1
        if len(self.counts) > self.max_size:
            oldest_key = next(iter(self.counts))
            del self.counts[oldest_key]
    
    def get_top(self, n=10):
        return sorted(self.counts.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def get(self, key, default=0):
        return self.counts.get(key, default)

class BoundedSet:
    def __init__(self, max_size=1000):
        self.max_size = max_size
        self.items = set()
    
    def add(self, item):
        if len(self.items) >= self.max_size:
            self.items.pop()
        self.items.add(item)
    
    def __contains__(self, item):
        return item in self.items
    
    def __len__(self):
        return len(self.items)

# Try to import real services, fall back to mocks if they fail
try:
    from geoip_service import GeoIPService as RealGeoIPService
    from asn_service import ASNService as RealASNService
    from ip_utils import BoundedCounter as RealBoundedCounter, BoundedSet as RealBoundedSet
    
    # Use real services if available
    GeoIPService = RealGeoIPService
    ASNService = RealASNService
    BoundedCounter = RealBoundedCounter
    BoundedSet = RealBoundedSet
    
    print("Using real geoip and ASN services")
    
except ImportError:
    print("Using mock geoip and ASN services")

import dashboard_config as cfg

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Suppress noisy whois library errors (connection refused, timeouts)
# Our ASN service already handles these gracefully with fallbacks
logging.getLogger('whois').setLevel(logging.CRITICAL)
logging.getLogger('whois.whois').setLevel(logging.CRITICAL)

app = Flask(__name__)
app.config['SECRET_KEY'] = cfg.SECRET_KEY or secrets.token_hex(32)

# CORS: restrict to specific origins (empty string = same-origin only)
cors_origins = cfg.CORS_ALLOWED_ORIGINS
if cors_origins:
    if isinstance(cors_origins, list):
        cors_list = cors_origins
    else:
        cors_list = [o.strip() for o in cors_origins.split(',') if o.strip()]
else:
    cors_list = []  # same-origin only

socketio = SocketIO(
    app,
    cors_allowed_origins=cors_list if cors_list else None,
    async_mode='eventlet'
)


# ============================================================================
# Authentication (optional)
# ============================================================================

def check_auth(username: str, password: str) -> bool:
    """Verify username/password against config."""
    return (username == cfg.DASHBOARD_USERNAME and
            password == cfg.DASHBOARD_PASSWORD)


def requires_auth(f):
    """Decorator for optional basic auth. Skipped if no credentials configured."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not cfg.DASHBOARD_USERNAME or not cfg.DASHBOARD_PASSWORD:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return Response(
                'Authentication required', 401,
                {'WWW-Authenticate': 'Basic realm="Cowrie Dashboard"'}
            )
        return f(*args, **kwargs)
    return decorated


# ============================================================================
# Simple Rate Limiter for API endpoints
# ============================================================================

class APIRateLimiter:
    """Per-IP rate limiter for API routes."""

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self._requests: Dict[str, list] = {}
        self._max = max_requests
        self._window = window_seconds
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            # Periodic cleanup of stale IPs (every 5 minutes)
            if now - self._last_cleanup > 300:
                stale = [k for k, v in self._requests.items()
                         if not v or now - v[-1] > self._window]
                for k in stale:
                    del self._requests[k]
                self._last_cleanup = now

            if ip not in self._requests:
                self._requests[ip] = []
            # Clean old entries
            self._requests[ip] = [t for t in self._requests[ip] if now - t < self._window]
            if len(self._requests[ip]) >= self._max:
                return False
            self._requests[ip].append(now)
            return True


# Parse API_RATE_LIMIT config (format: '30/minute' or '100/hour')
def _parse_rate_limit(rate_str: str) -> tuple:
    try:
        parts = rate_str.split('/')
        count = int(parts[0])
        unit = parts[1].lower() if len(parts) > 1 else 'minute'
        window = 3600 if unit.startswith('hour') else 60
        return count, window
    except (ValueError, IndexError):
        return 30, 60

_rl_max, _rl_window = _parse_rate_limit(cfg.API_RATE_LIMIT)
rate_limiter = APIRateLimiter(max_requests=_rl_max, window_seconds=_rl_window)


def rate_limited(f):
    """Decorator to rate-limit API routes."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr or 'unknown'
        if not rate_limiter.is_allowed(client_ip):
            return jsonify({'error': 'Rate limit exceeded'}), 429
        return f(*args, **kwargs)
    return decorated


# ============================================================================
# CowrieMonitor
# ============================================================================

class CowrieMonitor:
    """Real-time Cowrie log monitor with stats aggregation, alerting,
    async ASN enrichment, bounded collections, and cached summaries."""

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path or cfg.COWRIE_LOG_PATH
        self.geoip_service = GeoIPService()
        self.asn_service = ASNService()

        # Thread-safe stats lock
        self._lock = threading.Lock()

        # Bounded statistics
        self.stats: Dict[str, Any] = {
            'total_connections': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'commands_executed': 0,
            'unique_ips': BoundedSet(max_size=cfg.MAX_UNIQUE_IPS),
            'unique_passwords': BoundedSet(max_size=cfg.MAX_UNIQUE_PASSWORDS),
            'unique_users': BoundedSet(max_size=cfg.MAX_UNIQUE_USERS),
            'recent_attacks': deque(maxlen=cfg.MAX_RECENT_ATTACKS),
            'top_ips': BoundedCounter(max_size=cfg.MAX_TOP_ENTRIES),
            'top_passwords': BoundedCounter(max_size=cfg.MAX_TOP_ENTRIES),
            'top_users': BoundedCounter(max_size=cfg.MAX_TOP_ENTRIES),
            'top_commands': BoundedCounter(max_size=cfg.MAX_TOP_ENTRIES),
            'attack_timeline': deque(maxlen=cfg.MAX_TIMELINE_ENTRIES),
            'countries': BoundedCounter(max_size=500),  # ~200 countries max
            'organizations': BoundedCounter(max_size=cfg.MAX_TOP_ENTRIES),
            'asns': BoundedCounter(max_size=cfg.MAX_TOP_ENTRIES),
            'credentials': BoundedCounter(max_size=1000),  # Store captured credentials
            'map_data': {
                'markers': deque(maxlen=cfg.MAX_MAP_MARKERS),
                'heatpoints': deque(maxlen=cfg.MAX_MAP_MARKERS)
            },
            'alerts': deque(maxlen=cfg.MAX_ALERTS)
        }
        
        # Store all successful logins (last 2000)
        self.successful_logins = deque(maxlen=2000)
        
        # Track successful login sessions for action collection
        self.successful_sessions = {}  # session -> login_data

        self.alerts: deque = deque(maxlen=cfg.MAX_ALERTS)
        self._alerted_ips: BoundedSet = BoundedSet(max_size=10000)
        self._alerted_countries: BoundedSet = BoundedSet(max_size=500)
        self._alerted_orgs: BoundedSet = BoundedSet(max_size=5000)

        self.running = True
        self.last_position = 0
        self._last_inode: Optional[int] = None

        # Cached stats summary
        self._stats_cache: Optional[Dict[str, Any]] = None
        self._stats_cache_time: float = 0.0
        self._stats_dirty = True

        # Async ASN enrichment queue
        self._enrich_queue: queue.Queue = queue.Queue(maxsize=cfg.ENRICHMENT_QUEUE_SIZE)

    def parse_log_entry(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single JSON log line. Returns None if not a valid JSON object."""
        try:
            parsed = json.loads(line.strip())
            # Ensure it's a dict — json.loads can return str/int/list
            if isinstance(parsed, dict):
                return parsed
            return None
        except (json.JSONDecodeError, ValueError):
            return None

    def _process_login(self, entry: Dict[str, Any], is_success: bool) -> None:
        """Common handler for login events (both success and failed)."""
        password = entry.get('password')
        username = entry.get('username')
        ip = entry.get('src_ip', 'Unknown')
        timestamp = entry.get('timestamp', '')
        country = entry.get('geo_location', {}).get('country', 'Unknown')
        organization = entry.get('asn_info', {}).get('organization', 'Unknown')
        latitude = entry.get('geo_location', {}).get('latitude')
        longitude = entry.get('geo_location', {}).get('longitude')

        if is_success:
            self.stats['successful_logins'] += 1
            # Store successful login details
            login_data = {
                'timestamp': timestamp,
                'ip': ip,
                'username': username,
                'password': password,
                'country': country,
                'organization': organization,
                'latitude': latitude,
                'longitude': longitude,
                'session': session,
                'type': 'cowrie.login.success',
                'actions': []
            }
            self.successful_logins.append(login_data)
            # Track the session for action collection
            self.successful_sessions[session] = login_data
            event_type = 'login.success'
        else:
            self.stats['failed_logins'] += 1
            event_type = 'login.failed'

        if password:
            self.stats['unique_passwords'].add(password)
            self.stats['top_passwords'].increment(password)

        if username:
            self.stats['unique_users'].add(username)
            self.stats['top_users'].increment(username)

        # Track credentials for export
        if username and password:
            self.stats['credentials'].increment(f"{username}:{password}")
        elif username:
            self.stats['credentials'].increment(f"{username}:<no_password>")
        elif password:
            self.stats['credentials'].increment(f"<no_username>:{password}")

        # Add login attempt to recent attacks
        self.stats['recent_attacks'].append({
            'timestamp': timestamp,
            'ip': ip,
            'event': event_type,
            'country': country,
            'organization': organization,
            'latitude': latitude,
            'longitude': longitude,
            'username': username,
            'password': password
        })

    def check_alerts(self, entry: Dict[str, Any]) -> None:
        """Check for alert conditions. Each IP/country/org is alerted only once."""
        ip = entry.get('src_ip', '')

        # High-frequency IP alert (only once per IP)
        if entry.get('eventid') == 'cowrie.session.connect':
            if self.stats['top_ips'].get(ip, 0) > 10 and ip not in self._alerted_ips:
                self._alerted_ips.add(ip)
                self._add_alert('HIGH', f'High frequency attacks from {ip}', entry)

        # Suspicious long password alert
        if entry.get('eventid') == 'cowrie.login.success':
            password = entry.get('password', '')
            if password and len(password) > 20:
                self._add_alert('MEDIUM', f'Suspicious long password from {ip}', entry)

        # GeoIP-based alert (once per country)
        # Note: countries are incremented in update_stats(), just check count here
        geo = entry.get('geo_location')
        if geo:
            country = geo.get('country', 'Unknown')
            if country != 'Unknown':
                count = self.stats['countries'].get(country, 0)
                if count > 20 and country not in self._alerted_countries:
                    self._alerted_countries.add(country)
                    self._add_alert('MEDIUM', f'High attack volume from {country}', entry)

        # ASN-based alert (once per org)
        # Note: organizations are incremented in _update_asn_stats(), just check count here
        asn_info = entry.get('asn_info')
        if asn_info and asn_info.get('organization'):
            org = asn_info['organization']
            count = self.stats['organizations'].get(org, 0)
            if count > 15 and org not in self._alerted_orgs:
                self._alerted_orgs.add(org)
                self._add_alert('MEDIUM', f'High attack volume from {org}', entry)

    def _add_alert(self, level: str, message: str, entry: Dict[str, Any]) -> None:
        """Add alert to queue and emit via WebSocket."""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message,
            'ip': entry.get('src_ip'),
            'country': entry.get('geo_location', {}).get('country', 'Unknown'),
            'organization': entry.get('asn_info', {}).get('organization', 'Unknown'),
        }
        self.alerts.append(alert)
        try:
            socketio.emit('alert', alert)
        except Exception as e:
            pass

    def _update_asn_stats(self, entry: Dict[str, Any]) -> None:
        """Update ASN-related stats from enriched entry (called from enrichment worker).
        Note: only called when inline ASN didn't find org (so no double-counting).
        Does NOT call check_alerts (already called in update_stats).
        """
        asn_info = entry.get('asn_info')
        if not asn_info:
            return

        with self._lock:
            org = asn_info.get('organization')
            asn = asn_info.get('asn')
            if org:
                self.stats['organizations'].increment(org)
            if asn:
                self.stats['asns'].increment(asn)
            self._stats_dirty = True

    def _enrichment_worker(self) -> None:
        """Background thread for slow ASN lookups. Decouples API calls from log processing."""
        logger.info("ASN enrichment worker started")
        while self.running:
            try:
                entry = self._enrich_queue.get(timeout=1)
                entry = self.asn_service.enrich_log_entry(entry)
                self._update_asn_stats(entry)

                # Emit enriched entry to clients
                try:
                    socketio.emit('enriched_entry', {
                        'src_ip': entry.get('src_ip'),
                        'asn_info': entry.get('asn_info')
                    })
                except Exception:
                    pass

            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Enrichment worker error: %s", e)
                time.sleep(1)

        logger.info("ASN enrichment worker stopped")

    def update_stats(self, entry: Dict[str, Any]) -> None:
        """Update statistics from a log entry (thread-safe).
        GeoIP and ASN enrichment done inline (fast, local DB).
        ASN falls back to async queue if local DB unavailable.
        """
        eventid = entry.get('eventid')
        ip = entry.get('src_ip')

        # GeoIP enrichment — fast local DB lookup, do inline
        entry = self.geoip_service.enrich_log_entry(entry)

        # ASN enrichment — local DB is instant, do inline
        entry = self.asn_service.enrich_log_entry(entry)

        with self._lock:
            if eventid == 'cowrie.session.connect':
                self.stats['total_connections'] += 1
                self.stats['unique_ips'].add(ip)
                self.stats['top_ips'].increment(ip)
                self.stats['recent_attacks'].append({
                    'timestamp': entry.get('timestamp'),
                    'ip': ip,
                    'event': 'connection',
                    'country': entry.get('geo_location', {}).get('country', 'Unknown'),
                    'organization': entry.get('asn_info', {}).get('organization', 'Unknown'),
                    'latitude': entry.get('geo_location', {}).get('latitude'),
                    'longitude': entry.get('geo_location', {}).get('longitude'),
                    'username': entry.get('username'),
                    'password': entry.get('password')
                })

            elif eventid == 'cowrie.login.failed':
                self._process_login(entry, is_success=False)

            elif eventid == 'cowrie.login.success':
                self._process_login(entry, is_success=True)

            elif eventid == 'cowrie.command.input':
                self.stats['commands_executed'] += 1
                cmd = entry.get('input', '')
                if cmd:
                    self.stats['top_commands'].increment(cmd)

            # Update map data if geolocated
            geo = entry.get('geo_location')
            if geo and geo.get('latitude') and geo.get('longitude'):
                self.stats['map_data']['markers'].append({
                    'lat': geo['latitude'],
                    'lng': geo['longitude'],
                    'ip': entry.get('src_ip'),
                    'country': geo['country'],
                    'city': geo.get('city'),
                    'timestamp': entry.get('timestamp'),
                    'event': eventid,
                    'username': entry.get('username'),
                    'organization': entry.get('asn_info', {}).get('organization', 'Unknown'),
                    'asn': entry.get('asn_info', {}).get('asn', 'Unknown')
                })
                self.stats['map_data']['heatpoints'].append({
                    'lat': geo['latitude'],
                    'lng': geo['longitude'],
                    'intensity': 1
                })

            # Update GeoIP country stats inline (fast)
            if geo:
                country = geo.get('country', 'Unknown')
                if country != 'Unknown':
                    self.stats['countries'].increment(country)

            # Update ASN/organization stats inline (local DB is instant)
            asn_data = entry.get('asn_info', {})
            org = asn_data.get('organization')
            asn = asn_data.get('asn')
            if org:
                self.stats['organizations'].increment(org)
            if asn:
                self.stats['asns'].increment(asn)

            # Update timeline - store simple count per timestamp
            timestamp = entry.get('timestamp')
            if timestamp:
                # Group attacks by minute for timeline
                time_key = timestamp  # Use full timestamp as key
                self.stats['attack_timeline'].append(time_key)

            self._stats_dirty = True

        # Check GeoIP-related alerts (outside lock)
        self.check_alerts(entry)

        # Queue ASN enrichment for background only if inline didn't find organization
        asn_info = entry.get('asn_info', {})
        if not asn_info.get('organization'):
            try:
                self._enrich_queue.put_nowait(entry)
            except queue.Full:
                pass
        
        # Collect actions for successful login sessions
        if eventid.startswith('cowrie.') and eventid != 'cowrie.login.success' and session in self.successful_sessions:
            action = {
                'type': eventid.replace('cowrie.', '').replace('.', '_'),
                'timestamp': entry.get('timestamp', ''),
                'details': {k: v for k, v in entry.items() if k not in ['timestamp', 'session', 'src_ip', 'eventid']}
            }
            self.successful_sessions[session]['actions'].append(action)

    def _detect_log_rotation(self) -> bool:
        """Detect if log file was rotated (truncated or replaced)."""
        try:
            stat = os.stat(self.log_path)
            current_inode = stat.st_ino
            current_size = stat.st_size

            # File truncated or replaced
            if current_size < self.last_position:
                logger.info("Log file rotation detected (size shrank from %d to %d)",
                           self.last_position, current_size)
                self.last_position = 0
                self._last_inode = current_inode
                return True

            # Inode changed (file replaced)
            if self._last_inode is not None and current_inode != self._last_inode:
                logger.info("Log file rotation detected (inode changed)")
                self.last_position = 0
                self._last_inode = current_inode
                return True

            self._last_inode = current_inode
            return False
        except OSError:
            return False

    def monitor_logs(self) -> None:
        """Monitor log file in real-time. Keeps file handle open, only reopens on rotation."""
        logger.info("Started monitoring: %s", self.log_path)
        file_handle = None

        # Load historical data from all log files
        if os.path.exists(self.log_path):
            logger.info("Loading historical data from all log files...")
            log_dir = os.path.dirname(self.log_path)
            base_name = os.path.basename(self.log_path)
            
            # Find all log files (current and rotated)
            pattern = os.path.join(log_dir, base_name + '*')
            log_files = glob.glob(pattern)
            
            # Sort by modification time (oldest first)
            log_files.sort(key=lambda x: os.path.getmtime(x))
            
            logger.info("Found %d log files to process", len(log_files))
            
            total_loaded = 0
            for log_file in log_files:
                logger.info("Processing log file: %s", log_file)
                try:
                    if log_file.endswith('.gz'):
                        with gzip.open(log_file, 'rt', encoding='utf-8', errors='replace') as f:
                            for line_num, line in enumerate(f, 1):
                                if not line.strip():
                                    continue
                                entry = self.parse_log_entry(line)
                                if entry:
                                    self.process_log_entry(entry)
                                if line_num % 1000 == 0:
                                    logger.info("Loaded %d entries from %s...", line_num, os.path.basename(log_file))
                    else:
                        with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                            for line_num, line in enumerate(f, 1):
                                if not line.strip():
                                    continue
                                entry = self.parse_log_entry(line)
                                if entry:
                                    self.process_log_entry(entry)
                                if line_num % 1000 == 0:
                                    logger.info("Loaded %d entries from %s...", line_num, os.path.basename(log_file))
                    
                    logger.info("Completed processing %s", log_file)
                    total_loaded += 1
                    
                except Exception as e:
                    logger.error("Error processing log file %s: %s", log_file, e)
            
            logger.info("Historical data loading completed from %d files", total_loaded)

        while self.running:
            try:
                if not os.path.exists(self.log_path):
                    if file_handle:
                        file_handle.close()
                        file_handle = None
                    time.sleep(2)
                    continue

                # Check for log rotation
                rotated = self._detect_log_rotation()

                # Open or reopen file handle
                if file_handle is None or rotated:
                    if file_handle:
                        file_handle.close()
                    file_handle = open(self.log_path, 'r', encoding='utf-8', errors='replace')
                    file_handle.seek(self.last_position)

                new_lines = file_handle.readlines()
                self.last_position = file_handle.tell()

                for line in new_lines:
                    if not line.strip():
                        continue
                    entry = self.parse_log_entry(line)
                    if entry:
                        self.update_stats(entry)
                        try:
                            socketio.emit('log_entry', entry)
                        except Exception as e:
                            pass

                time.sleep(cfg.LOG_POLL_INTERVAL)

            except Exception as e:
                logger.error("Error monitoring logs: %s", e)
                if file_handle:
                    try:
                        file_handle.close()
                    except Exception:
                        pass
                    file_handle = None
                time.sleep(5)

        if file_handle:
            file_handle.close()
        logger.info("Log monitoring stopped")

    def get_stats_summary(self) -> Dict[str, Any]:
        """Get statistics summary (thread-safe, cached for performance).
        Cache is invalidated when _stats_dirty flag is set by update_stats.
        """
        now = time.time()

        # Return cached version if fresh
        if (self._stats_cache is not None
                and not self._stats_dirty
                and (now - self._stats_cache_time) < cfg.STATS_CACHE_TTL):
            return self._stats_cache

        with self._lock:
            total_logins = self.stats['failed_logins'] + self.stats['successful_logins']
            success_rate = (self.stats['successful_logins'] / max(1, total_logins)) * 100

            summary = {
                'total_connections': self.stats['total_connections'],
                'failed_logins': self.stats['failed_logins'],
                'successful_logins': self.stats['successful_logins'],
                'commands_executed': self.stats['commands_executed'],
                'unique_ips': len(self.stats['unique_ips']),
                'unique_passwords': len(self.stats['unique_passwords']),
                'unique_users': len(self.stats['unique_users']),
                'success_rate': success_rate,
                'top_ips': self.stats['top_ips'].get_top(500),
                'top_passwords': self.stats['top_passwords'].get_top(500),
                'top_users': self.stats['top_users'].get_top(500),
                'top_commands': self.stats['top_commands'].get_top(500),
                'top_countries': self.stats['countries'].get_top(500),
                'top_organizations': self.stats['organizations'].get_top(500),
                'top_asns': self.stats['asns'].get_top(500),
                'recent_attacks': sorted(list(self.stats['recent_attacks'])[-cfg.MAX_RECENT_ATTACKS:], key=lambda x: x.get('timestamp', ''), reverse=True)[:cfg.MAX_RECENT_ATTACKS],
                'map_data': {
                    'markers': list(self.stats['map_data']['markers']),
                    'heatpoints': list(self.stats['map_data']['heatpoints'])
                },
                'alerts': list(self.alerts)
            }

            self._stats_cache = summary
            self._stats_cache_time = now
            self._stats_dirty = False

        return summary



    def stop(self) -> None:
        """Graceful shutdown."""
        logger.info("Stopping monitor...")
        self.running = False
        self.geoip_service.close()
        self.asn_service.close()


# Initialize monitor
monitor = CowrieMonitor()


# --- Flask Routes ---

@app.route('/')
@requires_auth
def index():
    """Main dashboard."""
    return render_template('index.html')


@app.route('/api/stats')
@requires_auth
@rate_limited
def get_stats():
    """Get current statistics."""
    return jsonify(monitor.get_stats_summary())


@app.route('/api/map')
@requires_auth
@rate_limited
def get_map_data():
    """Get map data."""
    with monitor._lock:
        data = {
            'markers': list(monitor.stats['map_data']['markers']),
            'heatpoints': list(monitor.stats['map_data']['heatpoints'])
        }
    return jsonify(data)


@app.route('/api/countries')
@requires_auth
@rate_limited
def get_countries():
    """Get country statistics."""
    return jsonify(monitor.stats['countries'].top(50))


@app.route('/api/organizations')
@requires_auth
@rate_limited
def get_organizations():
    """Get organization statistics."""
    return jsonify(monitor.stats['organizations'].top(50))


@app.route('/api/users')
@requires_auth
@rate_limited
def get_users():
    """Get user statistics."""
    return jsonify(monitor.stats['top_users'].top(50))


@app.route('/api/commands')
@requires_auth
@rate_limited
def get_commands():
    """Get command statistics."""
    return jsonify(monitor.stats['top_commands'].top(50))


@app.route('/api/export')
@requires_auth
@rate_limited
def export_stats():
    """Export all top statistics as CSV download (horizontal layout)."""
    import io
    import csv
    from itertools import zip_longest

    output = io.StringIO()
    writer = csv.writer(output)

    stats = monitor.get_stats_summary()

    # --- Header ---
    writer.writerow(['Cowrie Dashboard Export'])
    writer.writerow(['Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])

    # --- Overview: single horizontal row ---
    overview_headers = [
        'Total Connections', 'Failed Logins', 'Successful Logins',
        'Commands Executed', 'Unique IPs', 'Unique Passwords',
        'Unique Users', 'Success Rate'
    ]
    overview_values = [
        stats.get('total_connections', 0),
        stats.get('failed_logins', 0),
        stats.get('successful_logins', 0),
        stats.get('commands_executed', 0),
        stats.get('unique_ips', 0),
        stats.get('unique_passwords', 0),
        stats.get('unique_users', 0),
        f"{stats.get('success_rate', 0):.1f}%"
    ]
    writer.writerow(overview_headers)
    writer.writerow(overview_values)
    writer.writerow([])

    # --- Top sections: side-by-side columns ---
    sections = [
        ('IP', 'Count', 'top_ips'),
        ('Username', 'Count', 'top_users'),
        ('Password', 'Count', 'top_passwords'),
        ('Command', 'Count', 'top_commands'),
        ('Country', 'Count', 'top_countries'),
        ('Organization', 'Count', 'top_organizations'),
        ('ASN', 'Count', 'top_asns'),
    ]

    # Build sorted lists for each section
    columns = []
    header_row = []
    for label, count_label, key in sections:
        data = stats.get(key, {})
        sorted_data = sorted(data.items(), key=lambda x: x[1], reverse=True)
        columns.append(sorted_data)
        header_row.extend([label, count_label, ''])  # extra '' for gap column

    # Write headers (remove trailing gap)
    if header_row:
        writer.writerow(header_row[:-1])

    # Write rows side-by-side using zip_longest
    for row_items in zip_longest(*columns, fillvalue=('', '')):
        row = []
        for name, count in row_items:
            row.extend([name, count, ''])  # gap column between sections
        writer.writerow(row[:-1])  # remove trailing gap

    csv_content = output.getvalue()
    output.close()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=cowrie_stats_{timestamp}.csv'}
    )


@app.route('/api/export/credentials')
@requires_auth
@rate_limited
def export_credentials():
    """Export captured credentials as CSV download."""
    import io
    import csv

    success_only = request.args.get('success_only', 'false').lower() == 'true'

    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(['Timestamp', 'IP Address', 'Username', 'Password', 'Success', 'Session'])

    # Get credentials data from monitor stats
    credentials = []
    if hasattr(monitor, 'stats') and 'credentials' in monitor.stats:
        # Convert BoundedCounter to list and get last N credentials
        credentials_list = list(monitor.stats['credentials'].get_top(1000))
        for cred_pair, count in credentials_list:
            # Parse username:password format
            if ':' in cred_pair:
                username, password = cred_pair.split(':', 1)
            else:
                username, password = cred_pair, '<no_password>'
            
            credentials.append({
                'timestamp': '',  # Not available in credentials tracking
                'ip': '',  # Not available in credentials tracking
                'username': username,
                'password': password,
                'success': False,  # Default to failed, could be enhanced later
                'session': ''
            })

    for cred in credentials:
        writer.writerow([
            cred.get('timestamp', ''),
            cred.get('ip', ''),
            cred.get('username', ''),
            cred.get('password', ''),
            cred.get('success', False),
            cred.get('session', '')
        ])

    csv_content = output.getvalue()
    output.close()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'cowrie_credentials_{"success" if success_only else "all"}_{timestamp}.csv'

    return Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


@app.route('/api/export/logs')
@requires_auth
@rate_limited
def export_logs():
    """Export recent logs as JSON download."""
    import json

    limit = int(request.args.get('limit', 1000))
    format_type = request.args.get('format', 'json').lower()

    # Get recent log entries from monitor
    logs = []
    if hasattr(monitor, 'stats') and 'recent_attacks' in monitor.stats:
        recent_attacks = monitor.stats['recent_attacks']
        if recent_attacks and len(recent_attacks) > 0:
            # Convert deque to list and get last N attacks
            attacks_list = list(recent_attacks)
            # Get last N attacks or all if fewer than N
            start_idx = max(0, len(attacks_list) - limit)
            attacks_to_export = attacks_list[start_idx:]
            for attack in attacks_to_export:
                logs.append({
                    'timestamp': attack.get('timestamp', ''),
                    'eventid': attack.get('type', ''),
                    'ip': attack.get('ip', ''),
                    'session': attack.get('session', ''),
                    'message': attack.get('message', ''),
                    'data': attack.get('data', {})
                })

    if format_type == 'csv':
        import io
        import csv

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(['Timestamp', 'Event ID', 'IP Address', 'Session', 'Message', 'Data'])

        for log in logs:
            writer.writerow([
                log.get('timestamp', ''),
                log.get('eventid', ''),
                log.get('ip', ''),
                log.get('session', ''),
                log.get('message', ''),
                json.dumps(log.get('data', {}))
            ])

        content = output.getvalue()
        output.close()
        mimetype = 'text/csv'
        ext = 'csv'
    else:
        content = json.dumps(logs, indent=2, default=str)
        mimetype = 'application/json'
        ext = 'json'

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'cowrie_logs_{timestamp}.{ext}'

    return Response(
        content,
        mimetype=mimetype,
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


@app.route('/api/export/alerts')
@requires_auth
@rate_limited
def export_alerts():
    """Export alerts as CSV download."""
    import io
    import csv

    limit = int(request.args.get('limit', 1000))

    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(['Timestamp', 'Level', 'Message', 'IP Address'])

    # Get alerts data from monitor (simple approach for now)
    alerts = []
    # Since alerts are not stored in monitor.stats, create sample alerts or use recent attacks as proxy
    if hasattr(monitor, 'stats') and 'recent_attacks' in monitor.stats:
        recent_attacks = monitor.stats['recent_attacks']
        if recent_attacks and len(recent_attacks) > 0:
            # Convert deque to list and get last N attacks
            attacks_list = list(recent_attacks)
            # Get last N attacks or all if fewer than N
            start_idx = max(0, len(attacks_list) - limit)
            attacks_to_export = attacks_list[start_idx:]
            for i, attack in enumerate(attacks_to_export):
                if i % 10 == 0:  # Create alerts for every 10th attack as example
                    alerts.append({
                        'timestamp': attack.get('timestamp', ''),
                        'level': 'WARNING' if attack.get('type') == 'cowrie.login.failed' else 'INFO',
                        'message': f"Suspicious activity from {attack.get('ip', 'unknown')}",
                        'ip': attack.get('ip', '')
                    })

    for alert in alerts:
        writer.writerow([
            alert.get('timestamp', ''),
            alert.get('level', ''),
            alert.get('message', ''),
            alert.get('ip', '')
        ])

    csv_content = output.getvalue()
    output.close()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'cowrie_alerts_{timestamp}.csv'

    return Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


@app.route('/api/health')
def health_check():
    """Health check endpoint (no auth required)."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'monitor_running': monitor.running,
        'log_file_exists': os.path.exists(monitor.log_path),
        'geoip_cache': monitor.geoip_service.get_cache_info(),
        'asn_cache': monitor.asn_service.get_cache_info()
    })


@app.route('/api/successful-logins')
@requires_auth
@rate_limited
def get_successful_logins():
    """Get successful login attempts."""
    try:
        if hasattr(monitor, 'successful_logins'):
            successful_logins = list(monitor.successful_logins)
            # Return last 1000 successful logins
            start_idx = max(0, len(successful_logins) - 1000)
            return jsonify(successful_logins[start_idx:])
        else:
            return jsonify([])
    except Exception as e:
        logger.error(f"Error getting successful logins: {e}")
        return jsonify({'error': str(e)}), 500


# --- WebSocket Handlers ---

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    logger.info('Client connected from %s', client_ip)
    emit('stats_update', monitor.get_stats_summary())


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    pass


@socketio.on('request_stats')
def handle_request_stats():
    """Handle manual stats request."""
    emit('stats_update', monitor.get_stats_summary())


# --- Background Tasks ---

def stats_push_loop() -> None:
    """Periodically push stats to all connected WebSocket clients.
    Replaces client-side HTTP polling — server pushes when data is available.
    """
    while monitor.running:
        try:
            if monitor._stats_dirty:
                socketio.emit('stats_update', monitor.get_stats_summary())
            time.sleep(cfg.STATS_PUSH_INTERVAL)
        except Exception as e:
            time.sleep(5)


# --- Startup ---

def start_monitoring() -> None:
    """Start monitoring and enrichment in background threads."""
    monitor_thread = threading.Thread(
        target=monitor.monitor_logs, daemon=True, name='log-monitor'
    )
    monitor_thread.start()

    enrichment_thread = threading.Thread(
        target=monitor._enrichment_worker, daemon=True, name='asn-enricher'
    )
    enrichment_thread.start()

    push_thread = threading.Thread(
        target=stats_push_loop, daemon=True, name='stats-push'
    )
    push_thread.start()


def graceful_shutdown(signum, frame):
    """Handle SIGTERM/SIGINT for graceful shutdown."""
    logger.info("Received signal %d, shutting down gracefully...", signum)
    monitor.stop()
    sys.exit(0)


if __name__ == '__main__':
    # Register signal handlers
    signal.signal(signal.SIGTERM, graceful_shutdown)
    signal.signal(signal.SIGINT, graceful_shutdown)

    start_monitoring()

    logger.info("Cowrie Real-time Dashboard starting...")
    logger.info("Access dashboard at: http://%s:%d", cfg.DASHBOARD_HOST, cfg.DASHBOARD_PORT)

    if cfg.DASHBOARD_USERNAME:
        logger.info("Basic authentication enabled (user: %s)", cfg.DASHBOARD_USERNAME)
    else:
        logger.warning("No authentication configured — dashboard is publicly accessible")

    try:
        socketio.run(app, host=cfg.DASHBOARD_HOST, port=cfg.DASHBOARD_PORT, debug=False)
    finally:
        monitor.stop()
