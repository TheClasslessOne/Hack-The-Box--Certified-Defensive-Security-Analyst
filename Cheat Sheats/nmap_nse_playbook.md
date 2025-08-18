# 🕵️ Network Enumeration with Nmap — Detailed Cheat Sheet

(Existing content with TTL notes, scans, workflows…)

---

# 🧩 Nmap NSE Scripts — Playbook by Category

> Tip: Run a whole category with `--script <category>` (e.g., `--script vuln`). Chain categories with commas or boolean logic: `--script "default or safe"`.

## 🔐 auth (authentication helpers)
- `ftp-anon` — Test anonymous FTP access.  
- `ssh-auth-methods` — List supported SSH auth methods.  
- `imap-capabilities` / `pop3-capabilities` / `smtp-commands` — Show supported auth/commands.  
- `http-auth` — Check for HTTP auth schemes.  
- `rtsp-auth` — RTSP auth check.  

## 📣 broadcast (L2/L3 discovery)
- `broadcast-dhcp-discover` — Discover DHCP servers.  
- `broadcast-dns-service-discovery` — mDNS/Bonjour discovery.  
- `broadcast-netbios-master-browser` — Find Windows master browser.  

## 🔨 brute (brute force; use with caution)
- `ftp-brute`, `ssh-brute`, `telnet-brute`, `imap-brute`, `pop3-brute`, `smtp-brute`  
- `mysql-brute`, `ms-sql-brute`, `oracle-brute`, `pgsql-brute`, `mongodb-brute`, `redis-brute`  
- `http-brute` — Generic HTTP auth brute.  

## 🧰 default (safe, fast)
- Run with `-sC` or `--script default`. Covers banner grabbing, basic checks, SSL info, etc.

## 🧭 discovery (enumeration)
- `banner` — Generic banner grab.  
- `dns-brute` — Subdomain brute-forcing.  
- `http-title`, `http-headers`, `http-methods`, `http-enum`, `http-robots.txt`, `http-vhosts`  
- `smb-os-discovery`, `smb-enum-shares`, `smb-enum-users`  
- `snmp-info` — sysDescr/sysName/etc.  
- `ssl-cert`, `ssl-enum-ciphers` — TLS cert & ciphers.  
- `rdp-enum-encryption` — RDP encryption.  
- `mysql-info`, `mysql-users`, `mongodb-info`, `redis-info`  
- `nfs-showmount` — List NFS shares.  

## 💥 dos (denial of service)
- `http-slowloris`, `http-slowloris-check` — Slowloris feasibility.  
*(Don’t use on prod!)*  

## 🎯 exploit (known vulns)
- `ftp-vsftpd-backdoor` — vsftpd 2.3.4 backdoor.  
- `irc-unrealircd-backdoor` — UnrealIRCd backdoor.  
- `http-shellshock` — Bash Shellshock CGI.  

## 🌍 external
- `http-google-malware`, `whois-*`, `ip-geolocation-*` (needs Internet).  

## 🧪 fuzzer
- `dns-fuzz`, `http-form-fuzzer`  

## 🚨 intrusive (noisy / state changing)
- `http-put` — Test PUT uploads.  
- `http-webdav-*` — WebDAV checks.  

## 🦠 malware
- `http-malware-host` — Known malware check.  
- `smb-double-pulsar-backdoor` — DoublePulsar detection.  

## 🛡️ safe
- `http-title`, `ssl-cert`, `ssh-hostkey`, `dns-recursion`, `ntp-info`  

## 🧾 version (fingerprinting helpers)
- `dns-nsid`, `ssh2-enum-algos`, `smtp-commands`  

## 🩺 vuln (vulnerability detection)
- `smb-vuln-ms17-010` — EternalBlue.  
- `ssl-heartbleed` — Heartbleed.  
- `http-sql-injection`, `http-dombased-xss`, `http-csrf`  
- `http-vuln-cve*` — CVE-specific checks.  

---

## 🔌 Protocol Shortlists

### 🌐 HTTP/HTTPS
`http-enum`, `http-title`, `http-headers`, `http-methods`, `http-robots.txt`,  
`http-auth`, `http-vhosts`, `http-sql-injection`, `ssl-enum-ciphers`, `ssl-heartbleed`

### 📂 SMB
`smb-os-discovery`, `smb-enum-shares`, `smb-enum-users`, `smb-vuln-ms17-010`

### 📨 Mail
`smtp-commands`, `smtp-enum-users`, `imap-capabilities`, `pop3-capabilities`

### 🔑 SSH
`ssh2-enum-algos`, `ssh-hostkey`, `ssh-auth-methods`, `ssh-brute`

### 🧠 Databases
`mysql-info`, `mysql-users`, `mysql-brute`, `ms-sql-info`, `pgsql-version`, `mongodb-info`, `redis-info`

### 📻 SNMP / RPC / NFS
`snmp-info`, `rpcinfo`, `nfs-showmount`

### 🛰️ RDP / VNC / Telnet
`rdp-enum-encryption`, `rdp-vuln-ms12-020`, `vnc-info`, `telnet-encryption`

---

## 🧪 How to Choose

1. Run full ports + versions  
   `nmap -p- -sV <IP>`  
2. Run discovery scripts on those ports  
   `nmap -sV --script discovery -p <ports> <IP>`  
3. Apply service-specific scripts (HTTP/SMB/FTP/etc.)  
4. Run vuln scripts for quick CVE checks  
   `nmap --script vuln -p <ports> <IP>`  
5. If still unsure, use manual tools (`nc`, `curl`, `smbclient`, etc.)  

---
