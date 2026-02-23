# Cowrie Honeypot Configuration Backup
# Server: 192.168.1.19
# Date: 2026-02-19
# Description: Full configuration and logs backup

## 📁 File Structure

```
192.168.1.19/
├── Configuration Files
│   ├── cowrie.cfg                 # Main Cowrie configuration
│   ├── cowrie.service             # Systemd service for Cowrie
│   └── cowrie-dashboard.service   # Dashboard service
│
├── Dashboard Files
│   ├── cowrie_dashboard_mobile.py # Mobile-optimized dashboard
│   ├── geoip_service.py          # GeoIP lookup service
│   ├── asn_service.py            # ASN/organization lookup
│   └── templates/                 # HTML templates
│       ├── index.html
│       ├── index_geo.html
│       ├── index_full.html
│       └── index_mobile.html
│
├── Logs
│   ├── logs/
│   │   ├── cowrie.json           # JSON format logs
│   │   └── cowrie.log            # Text format logs
│   ├── cowrie_service.log        # Service logs
│   ├── dashboard_service.log     # Dashboard service logs
│   ├── cowrie_status.log         # Current service status
│   ├── dashboard_status.log      # Dashboard status
│   ├── cowrie_processes.log     # Running processes
│   └── cowrie_ports.log          # Network ports
│
└── README.md                     # This file
```

## 🔧 Configuration Details

### Cowrie Service Status
- **Status:** Currently inactive (dead)
- **Last Run:** 2026-02-19 15:35:36 UTC (14 seconds duration)
- **Port:** 2222 (SSH honeypot)
- **User:** cowrie

### Dashboard Service Status
- **Status:** Active (running)
- **PID:** 9496
- **Memory:** 57.7MB
- **Port:** 3333 (Web dashboard)
- **Access:** http://192.168.1.19:3333

## 📊 Key Configuration Settings

### cowrie.cfg Highlights
```
listen_endpoints = tcp:2222:interface=0.0.0.0
auth_class = AuthRandom
auth_class_parameters = 100, 150, 100
```

### Service Configuration
- **User:** cowrie
- **Working Directory:** /home/cowrie/cowrie
- **Virtual Environment:** cowrie-env
- **Python Version:** 3.12.3

## 🌍 GeoIP & ASN Integration

### GeoIP Database
- **File:** GeoLite2-City.mmdb
- **Version:** 20260217
- **Provider:** MaxMind

### ASN Service Features
- **Sources:** WHOIS, IPInfo.io, IP-API.com
- **Caching:** Memory-based caching
- **Rate Limiting:** 1s delay between requests

## 📱 Mobile Dashboard Features

### Responsive Design
- **Framework:** Tailwind CSS
- **WebSocket:** Socket.IO with Eventlet
- **Charts:** Chart.js
- **Maps:** Leaflet.js with heatmap

### Mobile Optimizations
- **Touch-friendly controls**
- **Responsive grid layout**
- **Tab navigation**
- **Performance optimizations**

## 🚨 Security Configuration

### Authentication
- **Method:** AuthRandom (100-150 attempts)
- **Success Rate:** ~39%
- **Password Database:** Default + captured combinations

### Network Security
- **Listening Interface:** 0.0.0.0 (all interfaces)
- **Authbind:** Enabled for port 2222
- **Firewall:** Not configured (manual setup needed)

## 📈 Performance Metrics

### Resource Usage
- **Dashboard Memory:** 57.7MB
- **CPU Usage:** 1.4s total
- **Response Time:** <1s for dashboard
- **Concurrent Connections:** Eventlet-based

### Log Statistics
- **Total Connections:** 31+
- **Failed Logins:** 23+
- **Successful Logins:** 16+
- **Unique IPs:** 7+
- **Unique Countries:** Multiple

## 🔍 Troubleshooting Notes

### Common Issues
1. **Cowrie Service:** Currently stopped, needs restart
2. **Socket.IO Warning:** Session context errors (non-critical)
3. **Eventlet Patching:** Some warnings (functional)

### Recovery Commands
```bash
# Restart Cowrie
systemctl restart cowrie

# Check Dashboard
systemctl status cowrie-dashboard

# View Logs
journalctl -u cowrie -f
journalctl -u cowrie-dashboard -f
```

## 📝 Deployment Summary

### Installation Components
1. ✅ Cowrie honeypot installed
2. ✅ Python virtual environment
3. ✅ GeoIP database configured
4. ✅ ASN lookup service
5. ✅ Mobile dashboard deployed
6. ✅ Systemd services configured

### Current Status
- **Honeypot:** Stopped (needs restart)
- **Dashboard:** Running and accessible
- **Data Collection:** Logs available for analysis
- **Configuration:** All files backed up locally

## 🔄 Next Steps

1. **Restart Cowrie:** `systemctl restart cowrie`
2. **Configure Firewall:** Block malicious IPs
3. **Monitor Dashboard:** Check real-time activity
4. **Analyze Logs:** Review attack patterns
5. **Update GeoIP:** Refresh database monthly

---
**Backup completed:** 2026-02-19 23:30 UTC
**Total files:** 15+ configuration and log files
**Total size:** ~500KB compressed
