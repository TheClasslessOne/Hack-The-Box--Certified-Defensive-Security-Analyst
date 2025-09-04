# 📑 Table of Contents

- [🕵️ Network Enumeration with Nmap — Detailed Cheat Sheet](#-network-enumeration-with-nmap--detailed-cheat-sheet)
  - 🎯 Target Specification
  - 🔍 Host Discovery
  - 🚪 Port Scanning
  - 🎭 Evasion & Stealth
  - 📄 Output Options
  - ⚡ Performance & Timing
  - 🖥️ TTL Fingerprinting (Quick OS Guess)
  - 🛠 Practical Recon Workflows

- [📖 Master Nmap NSE Scripts Reference](#-master-nmap-nse-scripts-reference)
  - 📜 Useful NSE Scripts (Quick Reference)
  - 🧩 NSE Playbook (By Category + Protocol Shortlists)
  - 🕵️ Detailed NSE Scripts with Descriptions
  - ✅ Usage Workflow
  - 🚀 Handy One-Liners

---


# 🕵️ Network Enumeration with Nmap — Detailed Cheat Sheet

## 🎯 Target Specification
| Option | Description | Example |
|--------|-------------|---------|
| `10.10.10.0/24` | Scan entire subnet (CIDR notation). | `nmap 10.10.10.0/24` |
| `-iL hosts.txt` | Read list of targets from file. | `nmap -iL hosts.txt` |
| `-iR 100` | Choose 100 random targets. | `nmap -iR 100` |
| `--exclude 10.10.10.5` | Skip a host. | `nmap 10.10.10.0/24 --exclude 10.10.10.5` |
| `--exclude-file exclude.txt` | Exclude list of hosts from file. | `nmap --exclude-file exclude.txt 10.10.10.0/24` |

---

## 🔍 Host Discovery
| Option | Description | Example |
|--------|-------------|---------|
| `-sn` | Ping scan only (no port scan). | `nmap -sn 10.10.10.0/24` |
| `-Pn` | Treat all hosts as online (skip ping). Useful when ICMP is blocked. | `nmap -Pn target.com` |
| `-n` | Disable DNS resolution (faster). | `nmap -n 10.10.10.0/24` |
| `-PE` | ICMP Echo request ping. | `nmap -PE target.com` |
| `-PP` | ICMP Timestamp ping. | `nmap -PP target.com` |
| `-PM` | ICMP Netmask request ping. | `nmap -PM target.com` |
| `--disable-arp-ping` | Skip ARP discovery. Useful when scanning non-local subnets. | `nmap --disable-arp-ping 192.168.1.0/24` |
| `--packet-trace` | Show all packets sent/received. Great for debugging. | `nmap --packet-trace target.com` |
| `--reason` | Show why a port/host is marked open/closed. | `nmap --reason target.com` |

---

## 🚪 Port Scanning
| Option | Description | Example |
|--------|-------------|---------|
| `-p-` | Scan all 65,535 TCP ports. | `nmap -p- 10.10.10.10` |
| `-p22-110` | Scan port range. | `nmap -p22-110 10.10.10.10` |
| `-p22,25,80` | Specific ports only. | `nmap -p22,25,80 target.com` |
| `-F` | Fast scan (top 100 ports). | `nmap -F target.com` |
| `--top-ports=200` | Scan top 200 most common ports. | `nmap --top-ports=200 target.com` |
| `--exclude-ports 80,443` | Skip specific ports. | `nmap -p- --exclude-ports 80,443 target.com` |

### Scan Techniques
| Option | Description | Use Case |
|--------|-------------|----------|
| `-sS` | SYN scan (stealth). Default if root. | Fast + stealthy, doesn’t complete TCP handshake. |
| `-sT` | TCP connect scan. | Non-root scans, slower. |
| `-sA` | ACK scan. | Map firewall rules (detect filtered vs unfiltered). |
| `-sU` | UDP scan. | Discover DNS, SNMP, DHCP services. |
| `-sV` | Service/version detection. | Identify software versions. |
| `-sC` | Default script scan (safe NSE scripts). | Quick recon. |
| `--script <name>` | Run specific NSE script. | `nmap --script http-title target.com` |
| `--script vuln` | Run vulnerability detection scripts. | `nmap --script vuln target.com` |
| `-O` | OS detection. | Fingerprint the OS. |
| `-A` | Aggressive scan (OS + service + traceroute + scripts). | Thorough info gathering (loud!). |

---

## 🎭 Evasion & Stealth
| Option | Description | Example |
|--------|-------------|---------|
| `-D RND:5` | Use 5 random decoy IPs. | `nmap -D RND:5 target.com` |
| `-S <IP>` | Spoof source IP. | `nmap -S 10.10.10.200 target.com` |
| `-g <port>` | Use given source port. Sometimes evades filters (e.g., 53, 443). | `nmap -g 53 target.com` |
| `-e <iface>` | Choose network interface. | `nmap -e eth0 target.com` |
| `--dns-server <ns>` | Use specific DNS server. | `nmap --dns-server 8.8.8.8 target.com` |
| `--data-length 50` | Append random data to probes. | `nmap --data-length 50 target.com` |
| `--spoof-mac 0` | Randomize MAC address. | `nmap --spoof-mac 0 target.com` |

---

## 📄 Output Options
| Option | Description | Example |
|--------|-------------|---------|
| `-oA filename` | Save in all formats (`.nmap`, `.gnmap`, `.xml`). | `nmap -oA scan target.com` |
| `-oN file` | Normal human-readable output. | `nmap -oN results.txt target.com` |
| `-oG file` | Greppable format. | `nmap -oG grep.txt target.com` |
| `-oX file` | XML output (machine-parseable). | `nmap -oX results.xml target.com` |

---

## ⚡ Performance & Timing
| Option | Description | Example |
|--------|-------------|---------|
| `-T0` – `-T5` | Timing templates: paranoid (0), sneaky (1), polite (2), normal (3), aggressive (4), insane (5). | `nmap -T4 target.com` |
| `--max-retries <num>` | Limit probe retries. | `nmap --max-retries 2 target.com` |
| `--stats-every=5s` | Show scan progress every 5 sec. | `nmap --stats-every=5s target.com` |
| `--initial-rtt-timeout 50ms` | Set initial RTT timeout. | |
| `--max-rtt-timeout 100ms` | Set max RTT timeout. | |
| `--min-rate 300` | Send at least 300 packets/sec. | |
| `--max-rate 1000` | Cap sending rate at 1000 packets/sec. | |

---

## 🖥️ TTL Fingerprinting (Quick OS Guess)
| TTL Value | Likely OS |
|-----------|-----------|
| **64** | Linux/Unix, macOS, Android |
| **128** | Windows |
| **255** | Cisco/Networking devices |

### 🔧 Real-World TTL Tips
- **Router hops** reduce TTL by 1 per hop. Example: A Windows host with TTL=128 might show 124 after 4 hops.  
- Use `traceroute` (Linux) or `tracert` (Windows) to estimate hop count and adjust.  
- Compare observed TTL against defaults to guess the OS more accurately.  
- Combine TTL with TCP/IP fingerprinting (`nmap -O`) for better reliability.  

👉 Example: If ping reply shows `ttl=126`, likely a **Windows host** 2 hops away.

---

## 🛠 Practical Recon Workflows

**1. Fast discovery of live hosts**  
```bash
nmap -sn 10.10.10.0/24 -oG hosts.gnmap
```

**2. Full TCP + service/version scan**  
```bash
nmap -sS -sV -p- 10.10.10.10 -oA fullscan
```

**3. OS fingerprint + default scripts**  
```bash
nmap -A 10.10.10.10
```

**4. UDP discovery of common services**  
```bash
nmap -sU --top-ports 50 10.10.10.10
```

**5. Evade firewall with decoys and spoofed source**  
```bash
nmap -sS -D RND:10 -g 53 10.10.10.10
```

**6. Banner grabbing with version detection**  
```bash
nmap -sV --script=banner target.com
```

**7. Vulnerability detection with NSE**  
```bash
nmap --script vuln target.com
```

**8. Full stealth + output saved**  
```bash
sudo nmap -sS -T2 -p- -oA stealthscan target.com
```

---


---

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
