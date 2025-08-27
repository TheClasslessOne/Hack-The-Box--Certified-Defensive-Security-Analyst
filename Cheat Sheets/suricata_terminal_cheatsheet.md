# 🛡️ Suricata Terminal Cheat Sheet

Suricata is an **Intrusion Detection System (IDS)** and **Intrusion Prevention System (IPS)** that uses rules (similar to Snort) to detect malicious traffic.  

---

## 1. 🔹 Basic Commands

### Run Suricata live on an interface
```bash
sudo suricata -i eth0 -c /etc/suricata/suricata.yaml -v
```
- `-i eth0` → capture traffic on interface `eth0`.  
- `-c` → config file (default: `/etc/suricata/suricata.yaml`).  
- `-v` → verbose output.  

---

### Run Suricata against a PCAP file
```bash
sudo suricata -r traffic.pcap -c /etc/suricata/suricata.yaml
```
- `-r traffic.pcap` → read packets from file.  
- Logs/alerts go to `/var/log/suricata/`.  

---

### Test Suricata config for errors
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

---

## 2. 🔹 Rules Management

### Custom rule location
```bash
/etc/suricata/rules/local.rules
```

### Add a custom rule (example: TrickBot JA3)
```bash
echo 'alert tls any any -> any any (msg:"TrickBot JA3 Hash"; ja3.hash; content:"6734f37431670b3ab4292b8f60f29984"; sid:100001; rev:1;)' | sudo tee -a /etc/suricata/rules/local.rules
```

### Update ruleset
```bash
sudo suricata-update
```

---

## 3. 🔹 Logs & Monitoring

### Default log directory
```bash
cd /var/log/suricata/
```

Key files:  
- `fast.log` → quick human-readable alerts.  
- `eve.json` → JSON alerts for SIEM tools.  
- `stats.log` → performance stats.  
- `files.log` → file extraction logs.  

---

### Watch logs in real-time
```bash
tail -f /var/log/suricata/fast.log
```

### Pretty-print JSON logs
```bash
jq '.' /var/log/suricata/eve.json | less
```

---

## 4. 🔹 Examples in Terminal

### Detect suspicious User-Agent
Rule (`local.rules`):
```suricata
alert http any any -> any any (msg:"Suspicious User-Agent"; content:"curl"; http_header; sid:100002; rev:1;)
```

Test against PCAP:
```bash
sudo suricata -r suspicious_http.pcap -S /etc/suricata/rules/local.rules
```

---

### Detect TrickBot JA3 fingerprint
Rule:
```suricata
alert tls any any -> any any (msg:"TrickBot JA3"; ja3.hash; content:"4d7a28d6f2263ed61de88ca66eb011e3"; sid:100003; rev:1;)
```

Check alerts:
```bash
cat /var/log/suricata/fast.log
```

---

### Detect file downloads
Rule:
```suricata
alert http any any -> any any (msg:"EXE download"; file_data; content:"MZ"; offset:0; sid:100004; rev:1;)
```

Run:
```bash
sudo suricata -r malware_download.pcap
```

Check extracted files:
```bash
ls /var/log/suricata/files/
```

---

## 5. 🔹 Useful CLI Flags

| Flag | Meaning |
|------|---------|
| `-i eth0` | Capture live traffic on `eth0` |
| `-r file.pcap` | Read from PCAP |
| `-c file.yaml` | Use custom config |
| `-S rules.rules` | Load specific rules file |
| `-T` | Test config & rules |
| `-D` | Run in daemon mode |
| `-v` | Verbose output |

---

## 6. 🔹 Workflow for HTB Labs

1. **Uncomment/edit a rule** in `/home/htb-student/local.rules`.  
2. **Run Suricata** against the lab’s PCAP:  
   ```bash
   sudo suricata -r traffic.pcap -S /home/htb-student/local.rules
   ```
3. **Check `fast.log`** for alerts:  
   ```bash
   cat /var/log/suricata/fast.log
   ```
4. **Troubleshoot with `eve.json`**:  
   ```bash
   jq '.' /var/log/suricata/eve.json | less
   ```

---
