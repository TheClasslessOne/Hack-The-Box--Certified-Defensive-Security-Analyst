# 🛡️ Snort Terminal Cheat Sheet

Snort is a **Network Intrusion Detection System (NIDS)** and Intrusion Prevention System (IPS). It analyzes packets and uses **rules** to detect malicious traffic.  

---

## 1. 🔹 Basic Commands

### Run Snort live on an interface
```bash
sudo snort -i eth0 -c /etc/snort/snort.conf -A console
```
- `-i eth0` → interface to listen on.  
- `-c` → config file.  
- `-A console` → print alerts to terminal.  

---

### Run Snort against a PCAP
```bash
sudo snort -r traffic.pcap -c /etc/snort/snort.conf -A console
```
- `-r` → read packets from a file.  

---

### Test Snort configuration
```bash
sudo snort -T -c /etc/snort/snort.conf
```
- Validates config and rules.  

---

### Run in IDS mode (alert only)
```bash
sudo snort -c /etc/snort/snort.conf -i eth0 -A fast
```

### Run in IPS mode (drop traffic)
```bash
sudo snort -Q --daq afpacket -c /etc/snort/snort.conf -i eth0:eth1
```
- Requires inline mode (`-Q`).  
- `eth0:eth1` = bridge interfaces.  

---

## 2. 🔹 Rules Structure

General format:
```snort
action protocol src_ip src_port -> dst_ip dst_port (options)
```

- **action** → `alert`, `log`, `pass`, `drop`, `reject`.  
- **protocol** → `ip`, `tcp`, `udp`, `icmp`.  
- **src/dst** → IPs and ports (can use variables like `$HOME_NET`).  
- **options** → detection logic inside `(...)`.  

---

### Example
```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"HTTP outbound"; sid:100001; rev:1;)
```
- Alerts on outbound TCP traffic to port 80.  

---

## 3. 🔹 Common Rule Options

- `msg:"text";` → alert message.  
- `sid:100001;` → unique rule ID.  
- `rev:1;` → revision number.  
- `content:"string";` → match payload data.  
- `nocase;` → case-insensitive search.  
- `offset` / `depth` → control where to search in payload.  
- `pcre:"/regex/";` → regex match.  
- `flow:to_server,established;` → match traffic direction/state.  

---

### Example – Detect User-Agent
```snort
alert http any any -> any any (msg:"Curl UA detected"; content:"curl"; http_header; sid:100002; rev:1;)
```

---

## 4. 🔹 Protocol-Specific Keywords

### HTTP
- `http_uri` → match URL path.  
- `http_method` → GET/POST.  
- `http_header` → header fields.  
- `http_host` → Host field.  

```snort
alert http any any -> any any (msg:"Suspicious URL"; content:"/admin"; http_uri; sid:100003; rev:1;)
```

---

### DNS
- `dns_query;` → look at DNS requests.  

```snort
alert udp any any -> any 53 (msg:"Malicious DNS"; content:"badsite.com"; dns_query; sid:100004; rev:1;)
```

---

### ICMP
```snort
alert icmp any any -> any any (msg:"ICMP ping detected"; sid:100005; rev:1;)
```

---

## 5. 🔹 Logs & Output

Default log location:
```bash
/var/log/snort/
```

- `alert` → alerts in text form.  
- `snort.log.*` → binary packet logs.  

---

### View alerts in real-time
```bash
tail -f /var/log/snort/alert
```

### Convert binary logs to readable format
```bash
snort -r snort.log.123456789 -X
```

---

## 6. 🔹 Example Rules

### 1. Detect Nmap scan (TCP SYN)
```snort
alert tcp any any -> $HOME_NET any (msg:"Nmap SYN scan"; flags:S; sid:100006; rev:1;)
```

### 2. Detect suspicious .exe download
```snort
alert http any any -> $HOME_NET any (msg:"EXE download"; content:"MZ"; offset:0; sid:100007; rev:1;)
```

### 3. Detect RDP brute force attempts
```snort
alert tcp any any -> $HOME_NET 3389 (msg:"RDP brute force"; threshold:type both, track by_src, count 5, seconds 60; sid:100008; rev:1;)
```

### 4. Detect SQL injection attempt
```snort
alert http any any -> $HOME_NET any (msg:"SQL Injection"; content:"' OR 1=1 --"; nocase; http_uri; sid:100009; rev:1;)
```

---

## 7. 🔹 Useful CLI Flags

| Flag | Meaning |
|------|---------|
| `-i eth0` | Interface |
| `-r file.pcap` | Read from PCAP |
| `-c file.conf` | Config file |
| `-A fast` | Fast logging |
| `-A console` | Print to terminal |
| `-q` | Quiet mode |
| `-X` | Print full packet in hex/ASCII |
| `-T` | Test configuration |
| `-Q` | Inline IPS mode |

---

## 8. 🔹 Workflow for Labs

1. **Write/edit rules** in `/etc/snort/rules/local.rules`.  
2. **Test config**:  
   ```bash
   sudo snort -T -c /etc/snort/snort.conf
   ```
3. **Run against PCAP**:  
   ```bash
   sudo snort -r test.pcap -c /etc/snort/snort.conf -A console
   ```
4. **Check alerts**:  
   ```bash
   cat /var/log/snort/alert
   ```

---
