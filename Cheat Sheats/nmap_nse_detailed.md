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

