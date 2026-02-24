# Cowrie Honeypot Dashboard - Installation Guide

## 🚀 Quick Installation

### Prerequisites
- Ubuntu/Debian system
- Cowrie honeypot installed
- Python 3.8+
- SQLite3

### Step 1: Clone Repository
```bash
git clone https://github.com/hoanb1/cowrie-honeypot-192.168.1.19.git
cd cowrie-honeypot-192.168.1.19
```

### Step 2: Copy Files to Cowrie Directory
```bash
sudo cp -r * /home/cowrie/cowrie/etc/
sudo chown -R cowrie:cowrie /home/cowrie/cowrie/etc/
```

### Step 3: Install Python Dependencies
```bash
sudo -u cowrie /home/cowrie/cowrie/cowrie-env/bin/pip install flask flask-socketio eventlet
```

### Step 4: Setup Systemd Service
```bash
sudo cp /home/cowrie/cowrie/etc/cowrie-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cowrie-dashboard
sudo systemctl start cowrie-dashboard
```

### Step 5: Verify Installation
```bash
# Check service status
sudo systemctl status cowrie-dashboard

# Check dashboard is running
curl http://localhost:3333

# Check logs
sudo journalctl -u cowrie-dashboard -f
```

## 📱 Access Dashboard

- **URL:** `http://<your-server-ip>:3333`
- **Default Port:** 3333
- **Test Credentials:** `tester / TestCowrie!23`

## 🔧 Configuration

### Dashboard Configuration
Edit `/home/cowrie/cowrie/etc/dashboard.py` to customize:
- Database path
- Log file location
- Port settings
- Cache settings

### Cowrie Configuration
Ensure `/home/cowrie/cowrie/etc/cowrie.cfg` has:
- `auth_class = UserDB`
- Proper log paths configured

## 📊 Features

- **Real-time Monitoring:** Live attack feeds
- **CSV Export:** Export captured credentials
- **Mobile Optimized:** Responsive design
- **Alert System:** Multi-level security alerts
- **Performance Optimized:** SQLite with caching
- **GeoIP Support:** Geographic attack visualization

## 🛠️ Troubleshooting

### Service Won't Start
```bash
# Check permissions
sudo chown -R cowrie:cowrie /home/cowrie/cowrie/etc/

# Check Python path
sudo -u cowrie /home/cowrie/cowrie/cowrie-env/bin/python3 /home/cowrie/cowrie/etc/dashboard.py
```

### Database Issues
```bash
# Reset database
sudo -u cowrie rm /home/cowrie/cowrie/var/log/cowrie/dashboard.db
sudo systemctl restart cowrie-dashboard
```

### Port Conflicts
```bash
# Check what's using port 3333
sudo netstat -tlnp | grep 3333

# Change port in dashboard.py if needed
```

## 📈 Performance Tips

1. **Database Optimization:** SQLite with WAL mode enabled
2. **Memory Usage:** Dashboard uses ~256MB max
3. **CPU Usage:** Optimized for low resource consumption
4. **Log Rotation:** Configure logrotate for large deployments

## 🔒 Security Considerations

- Dashboard runs as unprivileged `cowrie` user
- No external dependencies required
- Local database only (no external connections)
- Firewall recommended for production

## 📞 Support

- **Documentation:** Check README.md
- **Issues:** GitHub Issues
- **Community:** Cowrie honeypot community

---

**Version:** 2.0 Optimized  
**Last Updated:** 2026-02-24
