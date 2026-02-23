# Cowrie Honeypot Configuration
**Server:** 192.168.1.19  
**Repository:** Public configuration with test credentials  
**Last Updated:** 2026-02-23

## 🚀 Quick Start

### Test Credentials
- **Username:** `tester`
- **Password:** `TestCowrie!23`
- **Port:** 2222 (SSH honeypot)

### Access Points
- **Honeypot:** `ssh tester@192.168.1.19 -p 2222`
- **Dashboard:** `http://192.168.1.19:3333` (if running)

## 📁 Repository Structure

```
192.168.1.19/
├── Configuration Files
│   ├── cowrie.cfg                 # Main Cowrie configuration
│   ├── cowrie.service             # Systemd service for Cowrie
│   ├── cowrie-dashboard.service   # Dashboard service
│   └── userdb.txt               # User database with test credentials
│
├── Dashboard Files
│   ├── cowrie_dashboard_mobile.py # Mobile-optimized dashboard
│   ├── geoip_service.py          # GeoIP lookup service
│   ├── asn_service.py            # ASN/organization lookup
│   └── templates/               # HTML templates
│       ├── index.html
│       ├── index_geo.html
│       ├── index_full.html
│       └── index_mobile.html
│
└── README.md                    # This file
```

## 🔧 Configuration Details

### Authentication Setup
- **Method:** UserDB (fixed credentials)
- **Test Account:** `tester / TestCowrie!23`
- **Fallback:** Default Cowrie credentials for attackers

### Network Configuration
- **Listen Port:** 2222 (SSH honeypot)
- **Interface:** 0.0.0.0 (all interfaces)
- **User:** cowrie
- **Working Directory:** /home/cowrie/cowrie

### Service Management
```bash
# Start/stop Cowrie
systemctl start cowrie
systemctl stop cowrie
systemctl status cowrie

# Start/stop Dashboard
systemctl start cowrie-dashboard
systemctl stop cowrie-dashboard
```

## 📱 Dashboard Features

### Real-time Monitoring
- **Live Attack Feed:** Real-time connection attempts
- **GeoIP Mapping:** World map with attack origins
- **Statistics:** Success/failure rates, top IPs, passwords
- **Mobile Optimized:** Touch-friendly interface

### Technology Stack
- **Backend:** Flask + Socket.IO
- **Frontend:** Tailwind CSS + Chart.js
- **Maps:** Leaflet.js with heatmap
- **Real-time:** WebSocket updates

## 🛡️ Security Configuration

### Authentication Classes
- **UserDB:** Fixed credentials for testing
- **AuthRandom:** Random acceptance (commented out)
- **Backend:** Shell emulation

### Network Security
- **Authbind:** Enabled for privileged ports
- **Firewall:** Configure as needed
- **Isolation:** Cowrie runs as unprivileged user

## 📊 Statistics & Monitoring

### Credential Capture
The honeypot captures attacker credentials:
- **Failed Logins:** All attempts are logged
- **Successful Logins:** Grant access to fake environment
- **Data Storage:** JSON format in logs/

### Log Analysis
```bash
# View recent attacks
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json

# Extract credentials
grep -E "(login.failed|login.success)" /home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

## 🔍 Deployment Guide

### Initial Setup
1. **Clone Repository:**
   ```bash
   git clone https://github.com/hoanb1/cowrie-honeypot-192.168.1.19.git
   cd cowrie-honeypot-192.168.1.19
   ```

2. **Copy Configuration:**
   ```bash
   sudo cp -r * /home/cowrie/cowrie/etc/
   sudo chown -R cowrie:cowrie /home/cowrie/cowrie/etc/
   ```

3. **Start Services:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start cowrie
   sudo systemctl start cowrie-dashboard
   ```

### Testing Connection
```bash
# Test with provided credentials
ssh tester@192.168.1.19 -p 2222
# Password: TestCowrie!23

# Test with common attacker credentials
ssh root@192.168.1.19 -p 2222
# Password: 123456, admin, root, etc.
```

## 🚨 Important Notes

### Security Considerations
- **Isolation:** Ensure Cowrie runs in isolated environment
- **Monitoring:** Regularly review captured credentials
- **Updates:** Keep Cowrie and dependencies updated
- **Network:** Consider firewall rules to limit exposure

### Data Privacy
- **Logs:** May contain sensitive information
- **Credentials:** Store and handle securely
- **Compliance:** Follow local regulations for honeypot data

## 🔄 Maintenance

### Regular Tasks
1. **Log Rotation:** Configure logrotate for large log files
2. **GeoIP Updates:** Update MaxMind database monthly
3. **Backup:** Regular configuration backups
4. **Monitoring:** Check service status and resource usage

### Troubleshooting
```bash
# Check service status
systemctl status cowrie
journalctl -u cowrie -f

# Verify configuration
/home/cowrie/cowrie/cowrie-env/bin/cowrie --check-config

# Test authentication
ssh -v tester@192.168.1.19 -p 2222
```

## 📈 Performance Metrics

### Resource Usage
- **Memory:** ~50-100MB (depends on activity)
- **CPU:** Low usage, spikes during attacks
- **Storage:** Log growth depends on attack volume
- **Network:** Minimal overhead

### Scaling Considerations
- **Multiple Instances:** Configure different ports
- **Load Balancing:** Use HAProxy for distribution
- **Database:** Consider MySQL/PostgreSQL for large deployments

## 🤝 Contributing

### Configuration Changes
1. **Modify:** Edit configuration files locally
2. **Test:** Verify changes don't break functionality
3. **Commit:** Push changes with descriptive messages
4. **Deploy:** Apply to production environment

### Security Improvements
- **Additional Authentication Methods:** LDAP, database backends
- **Enhanced Logging:** Custom log formats and destinations
- **Alerting:** Email/Slack notifications for attacks
- **Integration:** SIEM systems, threat intelligence feeds

## 📞 Support

### Documentation
- **Cowrie Official:** https://cowrie.readthedocs.io/
- **GitHub Repository:** https://github.com/cowrie/cowrie
- **Community:** https://github.com/cowrie/cowrie/discussions

### Issues & Questions
- **Repository Issues:** Use GitHub Issues
- **Security Concerns:** Report privately
- **Configuration Help:** Check documentation first

---

**Repository Status:** ✅ Active  
**Last Configuration Update:** 2026-02-23  
**Test Credentials:** Available for validation  
**Dashboard:** Mobile-optimized real-time monitoring
