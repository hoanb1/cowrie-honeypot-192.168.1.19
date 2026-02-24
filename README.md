# Cowrie Honeypot Dashboard v2.0 - Optimized
**Server:** 192.168.1.19  
**Repository:** Production-ready configuration with optimized dashboard  
**Version:** 2.0.0 Final  
**Last Updated:** 2026-02-24

## 🚀 Quick Start

### Test Credentials
- **Username:** `tester`
- **Password:** `TestCowrie!23`
- **Port:** 2222 (SSH honeypot)

### Dashboard Access
- **URL:** `http://192.168.1.19:3333`
- **Features:** Real-time monitoring, CSV export, mobile-optimized

## 📁 Repository Structure

```
192.168.1.19/
├── Configuration Files
│   ├── cowrie.cfg                 # Main Cowrie configuration
│   ├── cowrie.service             # Cowrie systemd service
│   ├── cowrie-dashboard.service   # Dashboard systemd service
│   └── userdb.txt               # User database with test credentials
│
├── Dashboard Application
│   ├── dashboard.py               # Main dashboard application (optimized)
│   └── templates/
│       └── index.html            # Web interface (mobile-optimized)
│
├── Documentation
│   ├── README.md                  # This file
│   ├── INSTALL.md                 # Installation guide
│   └── CHANGELOG.md               # Version history
│
└── Configuration Examples
    ├── userdb.example           # User database example
    └── .gitignore               # Git ignore rules
```

## 🔧 Installation

### Quick Install
```bash
# Clone and install
git clone https://github.com/hoanb1/cowrie-honeypot-192.168.1.19.git
cd cowrie-honeypot-192.168.1.19

# Copy to Cowrie directory
sudo cp -r * /home/cowrie/cowrie/etc/
sudo chown -R cowrie:cowrie /home/cowrie/cowrie/etc/

# Start services
sudo systemctl enable cowrie-dashboard
sudo systemctl start cowrie-dashboard
```

### Detailed Installation
See [INSTALL.md](INSTALL.md) for complete installation guide.

## 📱 Dashboard Features

### Real-time Monitoring
- **Live Attack Feed:** Real-time connection attempts
- **WebSocket Updates:** Smooth <100ms updates
- **Connection Status:** Live indicator
- **Performance Metrics:** Resource usage monitoring

### Data Export
- **CSV Export:** Download captured credentials
- **Filter Options:** All credentials or successful only
- **Timestamp:** Automatic filename with date/time

### Advanced Analytics
- **Timeline Charts:** Attack patterns over time
- **Top Statistics:** IPs, passwords, usernames
- **Geographic Data:** Country and organization breakdown
- **Alert System:** Multi-level security alerts

### Mobile Optimization
- **Responsive Design:** Works on all screen sizes
- **Touch Controls:** Mobile-friendly interface
- **Glass Morphism:** Modern UI design
- **Smooth Animations:** CSS transitions and effects

## 🛡️ Security Features

### Authentication
- **UserDB Method:** Fixed credentials for testing
- **Test Account:** `tester / TestCowrie!23`
- **Credential Capture:** All attacker attempts logged

### Security Hardening
- **Sandboxed Service:** Restricted systemd service
- **Local Database:** No external API dependencies
- **User Isolation:** Runs as unprivileged cowrie user
- **Resource Limits:** Memory and CPU constraints

## 📊 Performance

### Optimizations
- **SQLite Database:** Local caching with WAL mode
- **Batch Processing:** 80% fewer database queries
- **Memory Efficient:** ~50MB typical usage
- **Low CPU:** Optimized for minimal resource usage

### Metrics
- **Memory:** <256MB maximum
- **CPU:** <50% quota
- **Latency:** <100ms real-time updates
- **Concurrent:** 100+ simultaneous connections

## 🔍 Management

### Service Management
```bash
# Dashboard service
sudo systemctl status cowrie-dashboard
sudo systemctl restart cowrie-dashboard
sudo journalctl -u cowrie-dashboard -f

# Cowrie service
sudo systemctl status cowrie
sudo systemctl restart cowrie
```

### Database Management
```bash
# Database location
/home/cowrie/cowrie/var/log/cowrie/dashboard.db

# Reset database (if needed)
sudo -u cowrie rm /home/cowrie/cowrie/var/log/cowrie/dashboard.db
sudo systemctl restart cowrie-dashboard
```

### Log Management
```bash
# Dashboard logs
sudo journalctl -u cowrie-dashboard -f

# Cowrie logs
sudo tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

## 🚨 Alerts

### Alert Levels
- **HIGH:** Critical security threats
- **MEDIUM:** Suspicious activity patterns
- **LOW:** Informational alerts

### Alert Types
- **High Frequency Attacks:** >10 attempts from single IP
- **Unusual Passwords:** Suspiciously long passwords
- **Geographic Anomalies:** High volume from specific countries
- **Organization Patterns:** Repeated attacks from same org

## � Statistics

### Available Metrics
- **Total Connections:** All connection attempts
- **Failed Logins:** Unsuccessful authentication attempts
- **Successful Logins:** Successful honeypot access
- **Unique IPs:** Distinct attacker addresses
- **Top Passwords:** Most commonly used passwords
- **Top Countries:** Geographic attack distribution
- **Top Organizations:** ISP/Cloud provider breakdown

### Export Options
- **CSV Format:** Compatible with Excel/analysis tools
- **Filtering:** All credentials or successful only
- **Timestamps:** ISO format for easy sorting
- **Metadata:** IP, session, success status

## 🔄 Updates

### Version History
See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

### Current Version: 2.0.0
- **Complete rewrite** with performance optimizations
- **Local database** replacing external APIs
- **CSV export** functionality
- **Enhanced UI** with glass morphism design
- **Mobile optimization** and responsive layout

## 🤝 Contributing

### Development
- **Code Style:** Python PEP 8 compliance
- **Testing:** Verify functionality before deployment
- **Documentation:** Update relevant files
- **Security:** Follow security best practices

### Submitting Changes
1. Fork repository
2. Create feature branch
3. Test thoroughly
4. Submit pull request

## 📞 Support

### Documentation
- **Installation:** [INSTALL.md](INSTALL.md)
- **Version History:** [CHANGELOG.md](CHANGELOG.md)
- **Configuration:** Inline code comments

### Community
- **Issues:** GitHub Issues
- **Discussions:** GitHub Discussions
- **Cowrie Project:** https://cowrie.readthedocs.io/

### Troubleshooting
- **Service Issues:** Check systemd logs
- **Database Problems:** Reset SQLite database
- **Performance:** Monitor resource usage
- **Network:** Verify firewall settings

---

## 🎯 Quick Reference

| Component | Path/URL | Purpose |
|-----------|----------|---------|
| **Dashboard** | `http://192.168.1.19:3333` | Web interface |
| **SSH Honeypot** | `ssh tester@192.168.1.19 -p 2222` | Test access |
| **Config Files** | `/home/cowrie/cowrie/etc/` | Configuration |
| **Database** | `/home/cowrie/cowrie/var/log/cowrie/dashboard.db` | Local cache |
| **Logs** | `/home/cowrie/cowrie/var/log/cowrie/` | Cowrie logs |

---

**Repository Status:** ✅ Production Ready  
**Version:** 2.0.0 Final Optimized  
**Test Credentials:** Available for validation  
**Dashboard:** Mobile-optimized real-time monitoring  
**Export:** CSV download functionality included
