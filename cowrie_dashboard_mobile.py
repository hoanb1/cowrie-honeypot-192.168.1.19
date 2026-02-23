#!/usr/bin/env python3
"""
Enhanced Cowrie Real-time Dashboard with GeoIP, ASN, and Mobile Support
Author: AI Assistant
Description: Real-time monitoring with geographic and organization attack visualization, mobile-optimized
"""

import json
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import os
import sys
import eventlet

# Add services to path
sys.path.append('/home/cowrie/cowrie')
from geoip_service import GeoIPService
from asn_service import ASNService

# Enable eventlet for better performance
eventlet.monkey_patch()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cowrie_monitor_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

class CowrieMonitor:
    def __init__(self, log_path='/home/cowrie/cowrie/var/log/cowrie/cowrie.json'):
        self.log_path = log_path
        self.geoip_service = GeoIPService()
        self.asn_service = ASNService()
        self.stats = {
            'total_connections': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'unique_ips': set(),
            'unique_passwords': set(),
            'unique_users': set(),
            'recent_attacks': deque(maxlen=100),
            'top_ips': defaultdict(int),
            'top_passwords': defaultdict(int),
            'top_users': defaultdict(int),
            'attack_timeline': deque(maxlen=50),
            'countries': defaultdict(int),
            'organizations': defaultdict(int),
            'asns': defaultdict(int),
            'map_data': {'markers': [], 'heatpoints': []}
        }
        self.alerts = deque(maxlen=50)
        self.running = True
        self.last_position = 0
        
    def parse_log_entry(self, line):
        """Parse a single log line"""
        try:
            return json.loads(line.strip())
        except json.JSONDecodeError:
            return None
    
    def check_alerts(self, entry):
        """Check for alert conditions"""
        if entry.get('eventid') == 'cowrie.session.connect':
            ip = entry.get('src_ip')
            if self.stats['top_ips'][ip] > 10:  # More than 10 attempts
                self.add_alert('HIGH', f'High frequency attacks from {ip}', entry)
        
        if entry.get('eventid') == 'cowrie.login.success':
            ip = entry.get('src_ip')
            password = entry.get('password')
            if len(password) > 20:  # Unusually long password
                self.add_alert('MEDIUM', f'Suspicious long password from {ip}', entry)
        
        # GeoIP-based alerts
        if 'geo_location' in entry:
            country = entry['geo_location']['country']
            if country != 'Unknown':
                self.stats['countries'][country] += 1
                if self.stats['countries'][country] > 20:  # High attacks from one country
                    self.add_alert('MEDIUM', f'High attack volume from {country}', entry)
        
        # ASN-based alerts
        if 'asn_info' in entry and entry['asn_info'].get('organization'):
            org = entry['asn_info']['organization']
            if org not in self.stats['organizations']:
                self.stats['organizations'][org] = 0
            self.stats['organizations'][org] += 1
            
            if self.stats['organizations'][org] > 15:  # High attacks from one organization
                self.add_alert('MEDIUM', f'High attack volume from {org}', entry)
    
    def add_alert(self, level, message, entry):
        """Add alert to queue"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message,
            'ip': entry.get('src_ip'),
            'country': entry.get('geo_location', {}).get('country', 'Unknown'),
            'organization': entry.get('asn_info', {}).get('organization', 'Unknown'),
            'details': entry
        }
        self.alerts.append(alert)
        socketio.emit('alert', alert)
    
    def update_stats(self, entry):
        """Update statistics"""
        eventid = entry.get('eventid')
        ip = entry.get('src_ip')
        username = entry.get('username')
        
        # Enrich with GeoIP and ASN data
        entry = self.geoip_service.enrich_log_entry(entry)
        entry = self.asn_service.enrich_log_entry(entry)
        
        if eventid == 'cowrie.session.connect':
            self.stats['total_connections'] += 1
            self.stats['unique_ips'].add(ip)
            self.stats['top_ips'][ip] += 1
            self.stats['recent_attacks'].append({
                'timestamp': entry.get('timestamp'),
                'ip': ip,
                'event': 'connection',
                'country': entry.get('geo_location', {}).get('country', 'Unknown'),
                'organization': entry.get('asn_info', {}).get('organization', 'Unknown')
            })
            
        elif eventid == 'cowrie.login.failed':
            self.stats['failed_logins'] += 1
            password = entry.get('password')
            if password:
                self.stats['unique_passwords'].add(password)
                self.stats['top_passwords'][password] += 1
            
            # Track username attempts
            if username:
                self.stats['unique_users'].add(username)
                self.stats['top_users'][username] += 1
                
        elif eventid == 'cowrie.login.success':
            self.stats['successful_logins'] += 1
            password = entry.get('password')
            if password:
                self.stats['unique_passwords'].add(password)
                self.stats['top_passwords'][password] += 1
            
            # Track successful usernames
            if username:
                self.stats['unique_users'].add(username)
                self.stats['top_users'][username] += 1
        
        # Update map data
        if 'geo_location' in entry and entry['geo_location']['latitude'] and entry['geo_location']['longitude']:
            location = entry['geo_location']
            
            # Add marker for individual attacks
            self.stats['map_data']['markers'].append({
                'lat': location['latitude'],
                'lng': location['longitude'],
                'ip': entry['src_ip'],
                'country': location['country'],
                'city': location['city'],
                'timestamp': entry.get('timestamp'),
                'event': entry.get('eventid'),
                'password': entry.get('password'),
                'username': entry.get('username'),
                'organization': entry.get('asn_info', {}).get('organization', 'Unknown'),
                'asn': entry.get('asn_info', {}).get('asn', 'Unknown')
            })
            
            # Add heatpoint for intensity
            self.stats['map_data']['heatpoints'].append({
                'lat': location['latitude'],
                'lng': location['longitude'],
                'intensity': 1
            })
            
            # Keep only last 1000 markers to avoid performance issues
            if len(self.stats['map_data']['markers']) > 1000:
                self.stats['map_data']['markers'] = self.stats['map_data']['markers'][-1000:]
            
            if len(self.stats['map_data']['heatpoints']) > 1000:
                self.stats['map_data']['heatpoints'] = self.stats['map_data']['heatpoints'][-1000:]
        
        # Update timeline
        self.stats['attack_timeline'].append({
            'timestamp': entry.get('timestamp'),
            'event': eventid,
            'ip': ip,
            'country': entry.get('geo_location', {}).get('country', 'Unknown'),
            'organization': entry.get('asn_info', {}).get('organization', 'Unknown'),
            'username': entry.get('username')
        })
    
    def monitor_logs(self):
        """Monitor log file in real-time"""
        while self.running:
            try:
                if os.path.exists(self.log_path):
                    with open(self.log_path, 'r') as f:
                        f.seek(self.last_position)
                        new_lines = f.readlines()
                        self.last_position = f.tell()
                        
                        for line in new_lines:
                            entry = self.parse_log_entry(line)
                            if entry:
                                self.update_stats(entry)
                                self.check_alerts(entry)
                                # Emit real-time update
                                socketio.emit('log_entry', entry)
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                print(f"Error monitoring logs: {e}")
                time.sleep(5)
    
    def get_stats_summary(self):
        """Get statistics summary"""
        return {
            'total_connections': self.stats['total_connections'],
            'failed_logins': self.stats['failed_logins'],
            'successful_logins': self.stats['successful_logins'],
            'unique_ips': len(self.stats['unique_ips']),
            'unique_passwords': len(self.stats['unique_passwords']),
            'unique_users': len(self.stats['unique_users']),
            'success_rate': (self.stats['successful_logins'] / max(1, self.stats['failed_logins'] + self.stats['successful_logins'])) * 100,
            'top_ips': dict(sorted(self.stats['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_passwords': dict(sorted(self.stats['top_passwords'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_users': dict(sorted(self.stats['top_users'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_countries': dict(sorted(self.stats['countries'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_organizations': dict(sorted(self.stats['organizations'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_asns': dict(sorted([(k, {'count': v, 'asn': k}) for k, v in self.stats['asns'].items()], key=lambda x: x[1]['count'], reverse=True)[:10]),
            'recent_attacks': list(self.stats['recent_attacks'])[-20:],
            'map_data': self.stats['map_data'],
            'alerts': list(self.alerts)
        }

# Initialize monitor
monitor = CowrieMonitor()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index_mobile.html')

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    return jsonify(monitor.get_stats_summary())

@app.route('/api/map')
def get_map_data():
    """Get map data"""
    return jsonify(monitor.stats['map_data'])

@app.route('/api/countries')
def get_countries():
    """Get country statistics"""
    return jsonify(dict(sorted(monitor.stats['countries'].items(), key=lambda x: x[1], reverse=True)))

@app.route('/api/organizations')
def get_organizations():
    """Get organization statistics"""
    return jsonify(dict(sorted(monitor.stats['organizations'].items(), key=lambda x: x[1], reverse=True)))

@app.route('/api/users')
def get_users():
    """Get user statistics"""
    return jsonify(dict(sorted(monitor.stats['top_users'].items(), key=lambda x: x[1], reverse=True)))

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'monitor_running': monitor.running,
        'log_file_exists': os.path.exists(monitor.log_path)
    })

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    print(f'Client connected from {client_ip}')
    emit('stats_update', monitor.get_stats_summary())

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

@socketio.on('request_stats')
def handle_request_stats():
    """Handle manual stats request"""
    emit('stats_update', monitor.get_stats_summary())

def start_monitoring():
    """Start monitoring in background"""
    monitor_thread = threading.Thread(target=monitor.monitor_logs, daemon=True)
    monitor_thread.start()

if __name__ == '__main__':
    start_monitoring()
    print("Cowrie Real-time Dashboard with GeoIP, ASN, and Mobile Support starting...")
    print("Access dashboard at: http://0.0.0.0:3333")
    print("Listening on all interfaces...")
    try:
        socketio.run(app, host='0.0.0.0', port=3333, debug=False)
    finally:
        monitor.geoip_service.close()
