# 📖 Master Nmap NSE Scripts Reference

This document combines **useful NSE scripts**, a **playbook by category**, and **detailed descriptions**.  
It includes ready-to-paste commands for fast use.

---

# 📜 Section 1: Useful NSE Scripts (Quick Reference)

# 📜 Useful Nmap NSE Scripts

## 🔎 General Enumeration
| Script | Purpose | Example |
|--------|---------|---------|
| `default` | Runs all “safe” scripts. | `nmap -sC 10.10.10.10` |
| `banner` | Grabs service banners. | `nmap --script banner -p80,22 10.10.10.10` |
| `http-title` | Gets webpage title. | `nmap --script http-title -p80 10.10.10.10` |
| `http-headers` | Dumps HTTP headers. | `nmap --script http-headers -p80 10.10.10.10` |
| `http-methods` | Checks allowed HTTP methods (GET, POST, PUT, etc.). | `nmap --script http-methods -p80 10.10.10.10` |

## 🔑 Authentication & Login
| Script | Purpose | Example |
|--------|---------|---------|
| `ftp-anon` | Check if FTP allows anonymous login. | `nmap --script ftp-anon -p21 10.10.10.10` |
| `ssh-auth-methods` | List supported SSH auth methods. | `nmap --script ssh-auth-methods -p22 10.10.10.10` |
| `smb-enum-users` | Enumerate SMB users. | `nmap --script smb-enum-users -p445 10.10.10.10` |
| `mysql-brute` | Attempt MySQL brute-force. | `nmap --script mysql-brute -p3306 10.10.10.10` |

## 🌐 Web / HTTP
| Script | Purpose | Example |
|--------|---------|---------|
| `http-enum` | Enumerates common web files/directories. | `nmap --script http-enum -p80 10.10.10.10` |
| `http-vhosts` | Detects virtual hosts. | `nmap --script http-vhosts -p80 10.10.10.10` |
| `http-robots.txt` | Fetches robots.txt. | `nmap --script http-robots.txt -p80 10.10.10.10` |
| `http-config-backup` | Finds backup config files. | `nmap --script http-config-backup -p80 10.10.10.10` |
| `http-phpmyadmin-dir-traversal` | Checks phpMyAdmin traversal vuln. | `nmap --script http-phpmyadmin-dir-traversal -p80 10.10.10.10` |

## 📂 SMB / Windows
| Script | Purpose | Example |
|--------|---------|---------|
| `smb-os-discovery` | Detect Windows version/domain. | `nmap --script smb-os-discovery -p445 10.10.10.10` |
| `smb-enum-shares` | List SMB shares. | `nmap --script smb-enum-shares -p445 10.10.10.10` |
| `smb-enum-users` | Enumerate users. | `nmap --script smb-enum-users -p445 10.10.10.10` |
| `smb-vuln-ms17-010` | Test for EternalBlue vuln. | `nmap --script smb-vuln-ms17-010 -p445 10.10.10.10` |
| `smb-vuln*` | Run all SMB vuln checks. | `nmap --script smb-vuln* -p445 10.10.10.10` |

## 📡 Other Services
| Script | Purpose | Example |
|--------|---------|---------|
| `dns-brute` | Enumerate subdomains. | `nmap --script dns-brute target.com` |
| `rdp-enum-encryption` | Checks RDP encryption methods. | `nmap --script rdp-enum-encryption -p3389 10.10.10.10` |
| `rdp-vuln-ms12-020` | Check RDP DoS vuln. | `nmap --script rdp-vuln-ms12-020 -p3389 10.10.10.10` |
| `mysql-info` | Collect MySQL server info. | `nmap --script mysql-info -p3306 10.10.10.10` |
| `snmp-info` | SNMP sysDescr, sysName, etc. | `nmap --script snmp-info -p161 10.10.10.10` |

## 💣 Vulnerability Scanning
| Script | Purpose | Example |
|--------|---------|---------|
| `vuln` | Run all vulnerability scripts. | `nmap --script vuln 10.10.10.10` |
| `http-vuln-cve2006-3392` | Check WebDAV exploit. | `nmap --script http-vuln-cve2006-3392 -p80 10.10.10.10` |
| `ftp-vsftpd-backdoor` | Detects vsftpd backdoor (2.3.4). | `nmap --script ftp-vsftpd-backdoor -p21 10.10.10.10` |
| `ssl-heartbleed` | Checks for Heartbleed vuln. | `nmap --script ssl-heartbleed -p443 10.10.10.10` |
| `http-sql-injection` | Test for basic SQLi. | `nmap --script http-sql-injection -p80 10.10.10.10` |


---

# 🧩 Section 2: NSE Playbook (By Category + Protocol Shortlists)

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


---

# 🕵️ Section 3: Detailed NSE Scripts with Descriptions

# 🕵️ Nmap NSE Scripts — Detailed Playbook

This playbook organizes **Nmap Scripting Engine (NSE)** scripts by category, with **script name, purpose, and practical usage**.

---

## 🔐 auth (authentication-related)
| Script | Description | Example |
|--------|-------------|---------|
| `ftp-anon` | Tests if FTP allows anonymous login. Useful for finding public file shares. | `nmap --script ftp-anon -p21 <IP>` |
| `ssh-auth-methods` | Lists SSH authentication methods (password, publickey, etc.). | `nmap --script ssh-auth-methods -p22 <IP>` |
| `imap-capabilities` | Shows IMAP server capabilities and supported auth methods. | `nmap --script imap-capabilities -p143 <IP>` |
| `pop3-capabilities` | Displays POP3 server features. | `nmap --script pop3-capabilities -p110 <IP>` |
| `smtp-commands` | Lists supported SMTP commands. | `nmap --script smtp-commands -p25 <IP>` |
| `http-auth` | Checks supported HTTP authentication schemes. | `nmap --script http-auth -p80 <IP>` |
| `rtsp-auth` | Tests RTSP authentication support. | `nmap --script rtsp-auth -p554 <IP>` |

---

## 📣 broadcast (discovery on local subnets)
| Script | Description | Example |
|--------|-------------|---------|
| `broadcast-dhcp-discover` | Finds DHCP servers on the network. | `nmap --script broadcast-dhcp-discover` |
| `broadcast-dns-service-discovery` | Detects mDNS/Bonjour services. | `nmap --script broadcast-dns-service-discovery` |
| `broadcast-netbios-master-browser` | Identifies Windows master browser. | `nmap --script broadcast-netbios-master-browser` |
| `broadcast-ssh` | Discovers SSH servers via broadcast. | `nmap --script broadcast-ssh` |

---

## 🔨 brute (brute-force attempts — use with permission)
| Script | Description | Example |
|--------|-------------|---------|
| `ftp-brute` | Brute-forces FTP logins. | `nmap --script ftp-brute -p21 <IP>` |
| `ssh-brute` | Attempts SSH password guessing. | `nmap --script ssh-brute -p22 <IP>` |
| `telnet-brute` | Brute-forces Telnet logins. | `nmap --script telnet-brute -p23 <IP>` |
| `http-brute` | Generic HTTP authentication brute force. | `nmap --script http-brute -p80 <IP>` |
| `mysql-brute` | Brute-forces MySQL logins. | `nmap --script mysql-brute -p3306 <IP>` |
| `ms-sql-brute` | Attempts MSSQL login brute force. | `nmap --script ms-sql-brute -p1433 <IP>` |
| `oracle-brute` | Tests Oracle DB credentials. | `nmap --script oracle-brute -p1521 <IP>` |
| `mongodb-brute` | Brute-forces MongoDB logins. | `nmap --script mongodb-brute -p27017 <IP>` |
| `redis-brute` | Tests Redis password authentication. | `nmap --script redis-brute -p6379 <IP>` |

---

## 🧭 discovery (enumeration without exploitation)
| Script | Description | Example |
|--------|-------------|---------|
| `banner` | Grabs banners from services. | `nmap --script banner -p22,80 <IP>` |
| `dns-brute` | Brute-forces subdomains. | `nmap --script dns-brute <domain>` |
| `http-title` | Retrieves webpage titles. | `nmap --script http-title -p80 <IP>` |
| `http-headers` | Displays HTTP headers. | `nmap --script http-headers -p80 <IP>` |
| `http-methods` | Shows supported HTTP methods. | `nmap --script http-methods -p80 <IP>` |
| `http-enum` | Enumerates common web paths. | `nmap --script http-enum -p80 <IP>` |
| `http-robots.txt` | Retrieves robots.txt file. | `nmap --script http-robots.txt -p80 <IP>` |
| `http-vhosts` | Detects virtual hosts. | `nmap --script http-vhosts -p80 <IP>` |
| `smb-os-discovery` | Finds Windows OS version/domain info. | `nmap --script smb-os-discovery -p445 <IP>` |
| `smb-enum-shares` | Lists available SMB shares. | `nmap --script smb-enum-shares -p445 <IP>` |
| `smb-enum-users` | Enumerates SMB users. | `nmap --script smb-enum-users -p445 <IP>` |
| `snmp-info` | Gets SNMP system info. | `nmap --script snmp-info -p161 <IP>` |
| `ssl-cert` | Retrieves SSL certificate details. | `nmap --script ssl-cert -p443 <IP>` |
| `ssl-enum-ciphers` | Lists SSL/TLS ciphers. | `nmap --script ssl-enum-ciphers -p443 <IP>` |
| `rdp-enum-encryption` | Checks RDP encryption methods. | `nmap --script rdp-enum-encryption -p3389 <IP>` |
| `mysql-info` | Collects MySQL info. | `nmap --script mysql-info -p3306 <IP>` |
| `nfs-showmount` | Lists NFS shares. | `nmap --script nfs-showmount -p111 <IP>` |

---

## 🩺 vuln (vulnerability detection)
| Script | Description | Example |
|--------|-------------|---------|
| `smb-vuln-ms17-010` | Tests for EternalBlue. | `nmap --script smb-vuln-ms17-010 -p445 <IP>` |
| `ssl-heartbleed` | Detects Heartbleed vuln. | `nmap --script ssl-heartbleed -p443 <IP>` |
| `ftp-vsftpd-backdoor` | Finds vsftpd 2.3.4 backdoor. | `nmap --script ftp-vsftpd-backdoor -p21 <IP>` |
| `http-sql-injection` | Tests for SQL injection flaws. | `nmap --script http-sql-injection -p80 <IP>` |
| `http-dombased-xss` | Detects DOM-based XSS. | `nmap --script http-dombased-xss -p80 <IP>` |
| `http-csrf` | Detects CSRF vulnerabilities. | `nmap --script http-csrf -p80 <IP>` |
| `rdp-vuln-ms12-020` | Checks for RDP DoS vuln. | `nmap --script rdp-vuln-ms12-020 -p3389 <IP>` |
| `samba-vuln-cve-2012-1182` | Tests for Samba vuln. | `nmap --script samba-vuln-cve-2012-1182 -p445 <IP>` |

---

## 🔧 Usage Tips
- Run all scripts in a category: `nmap --script vuln <IP>`
- Combine categories: `nmap --script "default or discovery" <IP>`
- Run multiple scripts: `nmap --script ftp-anon,http-title <IP>`

---



---

# ✅ Usage Workflow

1. **Run a full port scan with version detection**  
   ```bash
   nmap -p- -sV <IP>
   ```

2. **Use discovery scripts for context**  
   ```bash
   nmap -sV --script discovery -p <open-ports> <IP>
   ```

3. **Apply service-specific scripts** (HTTP, SMB, FTP, etc.)  

4. **Run vuln scripts for CVE checks**  
   ```bash
   nmap --script vuln -p <open-ports> <IP>
   ```

5. **Manually verify results** using tools like `nc`, `curl`, `smbclient`, etc.

---

# 🚀 Handy One-Liners

- **Quick banner + version info**  
  ```bash
  nmap -sV --script banner -p- <IP>
  ```

- **Run all safe default scripts**  
  ```bash
  nmap -sC <IP>
  ```

- **SMB Enumeration**  
  ```bash
  nmap -p445 --script "smb-os-discovery,smb-enum-shares,smb-enum-users" <IP>
  ```

- **HTTP/HTTPS Deep Enumeration**  
  ```bash
  nmap -p80,443 --script "http-enum,http-title,http-headers,http-methods,ssl-enum-ciphers" <IP>
  ```

- **Run all vuln checks**  
  ```bash
  nmap -sV --script vuln -p <open-ports> <IP>
  ```

---
