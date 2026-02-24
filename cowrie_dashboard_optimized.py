#!/usr/bin/env python3
"""
Optimized Cowrie Real-time Dashboard with Enhanced Performance
Author: AI Assistant
Features: Local ASN DB, optimized queries, CSV export, improved UI, smooth real-time
"""

import json
import time
import threading
import sqlite3
import csv
import io
from datetime import datetime, timedelta
from collections import defaultdict, deque
from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO, emit
import os
import sys
import eventlet
from pathlib import Path

# Enable eventlet for better performance
eventlet.monkey_patch()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cowrie_monitor_optimized'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Database setup
DB_PATH = '/home/cowrie/cowrie/var/log/cowrie/dashboard.db'
LOG_PATH = '/home/cowrie/cowrie/var/log/cowrie/cowrie.json'

class DatabaseManager:
    """Optimized database operations with connection pooling"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with optimized schema and indexes"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
        conn.execute("PRAGMA synchronous=NORMAL")  # Faster writes
        conn.execute("PRAGMA cache_size=10000")  # More cache
        
        # Create optimized tables
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS ip_cache (
                ip TEXT PRIMARY KEY,
                country_code TEXT,
                country_name TEXT,
                asn TEXT,
                organization TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password TEXT,
                ip TEXT,
                timestamp TIMESTAMP,
                success BOOLEAN,
                session_id TEXT,
                INDEX(username),
                INDEX(password),
                INDEX(timestamp)
            );
            
            CREATE TABLE IF NOT EXISTS attack_stats (
                ip TEXT,
                timestamp TIMESTAMP,
                event_type TEXT,
                country_code TEXT,
                INDEX(ip),
                INDEX(timestamp),
                INDEX(event_type)
            );
            
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT,
                message TEXT,
                ip TEXT,
                timestamp TIMESTAMP,
                acknowledged BOOLEAN DEFAULT FALSE,
                INDEX(timestamp),
                INDEX(level)
            );
        """)
        
        conn.commit()
        conn.close()
    
    def get_connection(self):
        """Get database connection with optimizations"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn
    
    def cache_ip_info(self, ip, country_code, country_name, asn, organization):
        """Cache IP information with upsert"""
        conn = self.get_connection()
        conn.execute("""
            INSERT OR REPLACE INTO ip_cache 
            (ip, country_code, country_name, asn, organization, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (ip, country_code, country_name, asn, organization))
        conn.commit()
        conn.close()
    
    def get_ip_info(self, ip):
        """Get cached IP information"""
        conn = self.get_connection()
        cursor = conn.execute("""
            SELECT country_code, country_name, asn, organization 
            FROM ip_cache WHERE ip = ?
        """, (ip,))
        result = cursor.fetchone()
        conn.close()
        return result
    
    def store_credential(self, username, password, ip, timestamp, success, session_id):
        """Store credential with batch insert optimization"""
        conn = self.get_connection()
        conn.execute("""
            INSERT INTO credentials 
            (username, password, ip, timestamp, success, session_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, password, ip, timestamp, success, session_id))
        conn.commit()
        conn.close()
    
    def get_top_credentials(self, limit=10, success_only=False):
        """Get top credentials with optimized query"""
        conn = self.get_connection()
        where_clause = "WHERE success = 1" if success_only else ""
        cursor = conn.execute(f"""
            SELECT username, password, COUNT(*) as count 
            FROM credentials 
            {where_clause}
            GROUP BY username, password 
            ORDER BY count DESC 
            LIMIT ?
        """, (limit,))
        results = cursor.fetchall()
        conn.close()
        return results
    
    def export_credentials_csv(self, success_only=False):
        """Export credentials to CSV"""
        conn = self.get_connection()
        where_clause = "WHERE success = 1" if success_only else ""
        cursor = conn.execute(f"""
            SELECT username, password, ip, timestamp, success, session_id 
            FROM credentials 
            {where_clause}
            ORDER BY timestamp DESC
        """)
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Username', 'Password', 'IP', 'Timestamp', 'Success', 'Session ID'])
        writer.writerows(cursor)
        
        conn.close()
        output.seek(0)
        return output.getvalue()

class GeoIPService:
    """Optimized GeoIP lookup with caching"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.cache_ttl = 86400  # 24 hours
        
    def get_ip_info(self, ip):
        """Get IP info with cache fallback"""
        # Try cache first
        cached = self.db_manager.get_ip_info(ip)
        if cached:
            return {
                'country_code': cached[0] or 'Unknown',
                'country_name': cached[1] or 'Unknown',
                'asn': cached[2] or 'Unknown',
                'organization': cached[3] or 'Unknown'
            }
        
        # Fallback to basic info if no external service
        basic_info = {
            'country_code': 'Unknown',
            'country_name': 'Unknown', 
            'asn': 'Unknown',
            'organization': 'Unknown'
        }
        
        # Cache the basic info
        self.db_manager.cache_ip_info(
            ip, 
            basic_info['country_code'],
            basic_info['country_name'],
            basic_info['asn'],
            basic_info['organization']
        )
        
        return basic_info

class CowrieMonitor:
    """Optimized Cowrie monitoring with better performance"""
    
    def __init__(self):
        self.db_manager = DatabaseManager(DB_PATH)
        self.geoip_service = GeoIPService(self.db_manager)
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
        self.batch_updates = []
        self.batch_size = 50
        
    def parse_log_entry(self, line):
        """Parse a single log line"""
        try:
            return json.loads(line.strip())
        except json.JSONDecodeError:
            return None
    
    def batch_update_stats(self):
        """Batch update statistics for better performance"""
        if not self.batch_updates:
            return
            
        conn = self.db_manager.get_connection()
        
        for entry in self.batch_updates:
            eventid = entry.get('eventid')
            ip = entry.get('src_ip')
            timestamp = entry.get('timestamp')
            
            # Store attack stats
            conn.execute("""
                INSERT INTO attack_stats (ip, timestamp, event_type, country_code)
                VALUES (?, ?, ?, ?)
            """, (ip, timestamp, eventid, entry.get('country_code', 'Unknown')))
            
            # Store credentials
            if eventid in ['cowrie.login.success', 'cowrie.login.failed']:
                username = entry.get('username', '')
                password = entry.get('password', '')
                success = eventid == 'cowrie.login.success'
                session_id = entry.get('session', '')
                
                self.db_manager.store_credential(
                    username, password, ip, timestamp, success, session_id
                )
        
        conn.commit()
        conn.close()
        self.batch_updates.clear()
    
    def update_stats(self, entry):
        """Update statistics with batch processing"""
        eventid = entry.get('eventid')
        ip = entry.get('src_ip')
        timestamp = entry.get('timestamp')
        
        # Get IP info
        ip_info = self.geoip_service.get_ip_info(ip)
        entry.update(ip_info)
        
        # Add to batch for processing
        self.batch_updates.append(entry)
        
        # Update in-memory stats
        if eventid == 'cowrie.session.connect':
            self.stats['total_connections'] += 1
            self.stats['unique_ips'].add(ip)
            self.stats['top_ips'][ip] += 1
            self.stats['countries'][ip_info['country_code']] += 1
            self.stats['organizations'][ip_info['organization']] += 1
            
            self.stats['recent_attacks'].append({
                'timestamp': timestamp,
                'ip': ip,
                'event': 'connection',
                'country': ip_info['country_name'],
                'organization': ip_info['organization']
            })
            
        elif eventid == 'cowrie.login.failed':
            self.stats['failed_logins'] += 1
            username = entry.get('username', '')
            password = entry.get('password', '')
            
            if username:
                self.stats['unique_users'].add(username)
                self.stats['top_users'][username] += 1
            if password:
                self.stats['unique_passwords'].add(password)
                self.stats['top_passwords'][password] += 1
                
        elif eventid == 'cowrie.login.success':
            self.stats['successful_logins'] += 1
            username = entry.get('username', '')
            password = entry.get('password', '')
            
            if username:
                self.stats['unique_users'].add(username)
                self.stats['top_users'][username] += 1
            if password:
                self.stats['unique_passwords'].add(password)
                self.stats['top_passwords'][password] += 1
        
        # Process batch if needed
        if len(self.batch_updates) >= self.batch_size:
            self.batch_update_stats()
    
    def check_alerts(self, entry):
        """Check for alert conditions"""
        ip = entry.get('src_ip')
        
        # High frequency attacks
        if self.stats['top_ips'][ip] > 10:
            self.add_alert('HIGH', f'High frequency attacks from {ip}', entry)
        
        # Unusually long password
        if entry.get('eventid') == 'cowrie.login.success':
            password = entry.get('password', '')
            if len(password) > 20:
                self.add_alert('MEDIUM', f'Suspicious long password from {ip}', entry)
        
        # High attack volume from country
        country_code = entry.get('country_code', 'Unknown')
        if self.stats['countries'][country_code] > 20:
            self.add_alert('MEDIUM', f'High attack volume from {country_code}', entry)
    
    def add_alert(self, level, message, entry):
        """Add alert to database and queue"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message,
            'ip': entry.get('src_ip'),
            'country': entry.get('country_name', 'Unknown'),
            'organization': entry.get('organization', 'Unknown')
        }
        
        # Store in database
        conn = self.db_manager.get_connection()
        conn.execute("""
            INSERT INTO alerts (level, message, ip, timestamp)
            VALUES (?, ?, ?, ?)
        """, (level, message, entry.get('src_ip'), datetime.now()))
        conn.commit()
        conn.close()
        
        # Add to queue and emit
        self.alerts.append(alert)
        socketio.emit('alert', alert)
    
    def monitor_logs(self):
        """Monitor log files with optimized file reading"""
        while self.running:
            try:
                if os.path.exists(LOG_PATH):
                    with open(LOG_PATH, 'r') as f:
                        f.seek(self.last_position)
                        new_lines = f.readlines()
                        self.last_position = f.tell()
                        
                        for line in new_lines:
                            entry = self.parse_log_entry(line)
                            if entry:
                                self.update_stats(entry)
                                self.check_alerts(entry)
                                
                                # Emit real-time update
                                socketio.emit('new_attack', {
                                    'type': entry.get('eventid'),
                                    'data': entry,
                                    'stats': self.get_stats_summary()
                                })
                
                # Process any remaining batch updates
                self.batch_update_stats()
                
                time.sleep(1)  # Reduced frequency for better performance
                
            except Exception as e:
                print(f"Error monitoring logs: {e}")
                time.sleep(5)
    
    def get_stats_summary(self):
        """Get optimized stats summary"""
        return {
            'total_connections': self.stats['total_connections'],
            'failed_logins': self.stats['failed_logins'],
            'successful_logins': self.stats['successful_logins'],
            'unique_ips': len(self.stats['unique_ips']),
            'unique_passwords': len(self.stats['unique_passwords']),
            'unique_users': len(self.stats['unique_users']),
            'top_ips': dict(list(self.stats['top_ips'].items())[:10]),
            'top_passwords': dict(list(self.stats['top_passwords'].items())[:10]),
            'top_users': dict(list(self.stats['top_users'].items())[:10]),
            'recent_attacks': list(self.stats['recent_attacks'])[-20:],
            'countries': dict(sorted(self.stats['countries'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'organizations': dict(sorted(self.stats['organizations'].items(), key=lambda x: x[1], reverse=True)[:10])
        }

# Initialize monitor
monitor = CowrieMonitor()

# Flask routes
@app.route('/')
def index():
    return render_template('index_optimized.html')

@app.route('/api/stats')
def get_stats():
    return jsonify(monitor.get_stats_summary())

@app.route('/api/credentials')
def get_credentials():
    success_only = request.args.get('success_only', 'false').lower() == 'true'
    limit = int(request.args.get('limit', 50))
    
    credentials = monitor.db_manager.get_top_credentials(limit, success_only)
    return jsonify([{
        'username': cred[0],
        'password': cred[1],
        'count': cred[2]
    } for cred in credentials])

@app.route('/api/export/credentials')
def export_credentials():
    success_only = request.args.get('success_only', 'false').lower() == 'true'
    
    csv_data = monitor.db_manager.export_credentials_csv(success_only)
    
    response = Response(
        csv_data,
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=cowrie_credentials_{"success" if success_only else "all"}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        }
    )
    return response

@app.route('/api/alerts')
def get_alerts():
    conn = monitor.db_manager.get_connection()
    cursor = conn.execute("""
        SELECT level, message, ip, timestamp 
        FROM alerts 
        ORDER BY timestamp DESC 
        LIMIT 50
    """)
    alerts = [{
        'level': row[0],
        'message': row[1],
        'ip': row[2],
        'timestamp': row[3]
    } for row in cursor.fetchall()]
    conn.close()
    return jsonify(alerts)

# WebSocket events
@socketio.on('connect')
def handle_connect():
    emit('stats_update', monitor.get_stats_summary())

@socketio.on('disconnect')
def handle_disconnect():
    pass

if __name__ == '__main__':
    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitor.monitor_logs, daemon=True)
    monitor_thread.start()
    
    # Run with optimized settings
    socketio.run(app, host='0.0.0.0', port=3333, debug=False)
