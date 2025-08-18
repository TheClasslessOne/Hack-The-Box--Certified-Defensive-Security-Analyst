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
