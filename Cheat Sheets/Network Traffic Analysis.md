# 🛡️ Network Traffic Analysis Cheat Sheet


⚠️ Unless you are running as root, `sudo` privileges are required for packet capture tools since they must set interfaces into **promiscuous mode** or bind to them.


## 🔹 Tcpdump (CLI Packet Capture)

Tcpdump is lightweight and fast — perfect for quick captures, filtering, and creating `.pcap` files for deeper analysis in Wireshark. Use `-nn` to avoid DNS/port lookups and speed things up.

### 🔧 Command Line Options
| Option | Description | Example |
|--------|-------------|---------|
| `-A` | Print frame payload in ASCII | `tcpdump -A -i eth0` |
| `-c <count>` | Exit after capturing count packets | `tcpdump -c 50 -i eth0` |
| `-D` | List available interfaces | `tcpdump -D` |
| `-e` | Print link-layer (e.g., MAC) headers | `tcpdump -e -i eth0` |
| `-F <file>` | Use file as filter expression | `tcpdump -F filter.txt` |
| `-G <n>` | Rotate dump every n seconds | `tcpdump -G 60 -w 'cap-%Y-%m-%d_%H-%M-%S.pcap'` |
| `-i <iface>` | Capture on interface | `tcpdump -i eth0` |
| `-K` | Don’t verify TCP checksums | `tcpdump -K -i eth0` |
| `-L` | List data link types for interface | `tcpdump -i eth0 -L` |
| `-n` / `-nn` | Don’t resolve names / names + ports | `tcpdump -nn -i eth0` |
| `-p` | Don’t enable promiscuous mode | `tcpdump -p -i eth0` |
| `-q` | Quick (less verbose) output | `tcpdump -q -i eth0` |
| `-r <file>` | Read from file | `tcpdump -r test.pcap` |
| `-s <len>` | Snaplen (0 = full packet) | `tcpdump -s 0 -i eth0` |
| `-S` | Absolute TCP sequence numbers | `tcpdump -S -i eth0` |
| `-t` | Don’t print timestamps | `tcpdump -t -i eth0` |
| `-v/-vv/-vvv` | Increase verbosity | `tcpdump -vvv -i eth0` |
| `-w <file>` | Write to file | `tcpdump -w out.pcap -i eth0` |
| `-x` / `-X` | Hex / Hex+ASCII payload | `tcpdump -X -i eth0` |
| `-y <type>` | Data link type | `tcpdump -y EN10MB -i eth0` |
| `-Z <user>` | Drop privs to user | `tcpdump -Z nobody -i eth0` |

---

## 🔍 Tcpdump Capture Filter Primitives (Cheat Sheet)

> Tip: Quote complex filters to avoid shell interpretation, e.g., `tcpdump -nn "tcp and port 443 and not net 10.0.0.0/8"`.

### 🎯 Host & Network
| Filter | Purpose | Example | When to Use |
|--------|---------|---------|-------------|
| `src host <ip>` / `dst host <ip>` | Match packets from/to an IP | `tcpdump src host 10.0.0.1` | Zoom in on one talker |
| `ether src host <mac>` / `ether dst host <mac>` | Match by MAC | `tcpdump ether src host 00:11:22:33:44:55` | Layer‑2 issues; IP churn/DHCP |
| `gateway host <ip>` | Packets routed via a gateway | `tcpdump gateway host 192.168.1.1` | Routing/bottleneck checks |
| `net <cidr>` | Subnet traffic | `tcpdump net 192.168.1.0/24` | Capture a whole segment |

### 🔌 Ports
| Filter | Purpose | Example | When to Use |
|--------|---------|---------|-------------|
| `port <p>` / `src|dst port <p>` | Single port / direction | `tcpdump tcp dst port 443` | Focus on one service |
| `portrange <p1>-<p2>` | Range of ports | `tcpdump udp portrange 5000-6000` | Ephemeral/service ranges |

### 📦 Packet Size
| Filter | Purpose | Example | When to Use |
|--------|---------|---------|-------------|
| `less <len>` | Packets ≤ length | `tcpdump less 64` | Pings, SYNs, scans |
| `greater <len>` | Packets ≥ length | `tcpdump greater 1500` | Jumbo/fragment issues |

### 📡 Protocols & Types
| Filter | Purpose | Example | When to Use |
|--------|---------|---------|-------------|
| `(ether|ip|ip6) proto <num>` | Protocol by number | `tcpdump ip proto 6` | TCP=6, UDP=17, ICMP=1 |
| `(ether|ip) broadcast` | Broadcasts | `tcpdump ether broadcast` | ARP storms, DHCP discover |
| `(ether|ip|ip6) multicast` | Multicasts | `tcpdump ip multicast` | mDNS, streaming, routing |
| `type (mgt|ctl|data)` | 802.11 Wi‑Fi frame type | `tcpdump type ctl` | Wi‑Fi L2 troubleshooting |
| `vlan [id]` | VLAN‑tagged traffic | `tcpdump vlan 100` | Verify trunk/tagging |
| `mpls [label]` | MPLS traffic | `tcpdump mpls 200` | WAN/MPLS analysis |

### 🔗 Built‑in Protocol Names
`arp, ether, fddi, icmp, ip, ip6, link, ppp, radio, rarp, slip, tcp, tr, udp, wlan`

### 🚩 TCP Flags (displayed via expressions)
| Task | Filter Expression | Example |
|------|-------------------|---------|
| SYNs only | `tcp[tcpflags] & tcp-syn != 0` | `tcpdump -nn "tcp[tcpflags] & tcp-syn != 0"` |
| RSTs only | `tcp[tcpflags] & tcp-rst != 0` | `tcpdump -nn "tcp[tcpflags] & tcp-rst != 0"` |
| ACKs only | `tcp[tcpflags] & tcp-ack != 0` | `tcpdump -nn "tcp[tcpflags] & tcp-ack != 0"` |

### ➕ Logical Operators
- `and` • `or` • `not`  
- `!` is also supported, but avoid it unquoted (your shell may interpret it).

### 💡 Example Filters
| Example | Description |
|--------|-------------|
| `tcpdump -nn "tcp and port 443 and not net 192.168.0.0/16"` | External HTTPS only (ignore internal) |
| `tcpdump -nn "udp and (port 53 or port 123)"` | DNS + NTP overview |
| `tcpdump -nn "icmp or icmp6"` | Connectivity and error checks |
| `tcpdump -nn "vlan 100 and not arp"` | VLAN 100, minus ARP noise |
| `tcpdump -nn "tcp[tcpflags] & tcp-syn != 0 and dst port 80"` | HTTP connection attempts (SYNs) |

---

## 🕵️ Tcpdump Review Filters (PCAP Analysis Cheat Sheet)

Use these during triage to narrow the dataset fast.

### 🔌 Ports & Services
| Task | Filter | Example |
|------|--------|---------|
| Single service | `port <p>` | `tcpdump port 80` |
| TCP to/from a port | `tcp src|dst port <p>` | `tcpdump tcp dst port 443` |
| UDP to/from a port | `udp src|dst port <p>` | `tcpdump udp src port 53` |
| Port range | `portrange <p1>-<p2>` | `tcpdump portrange 1024-65535` |

### 📡 Protocols
| Task | Filter | Example |
|------|--------|---------|
| TCP only | `tcp` | `tcpdump tcp` |
| UDP only | `udp` | `tcpdump udp` |
| ICMP only | `icmp` | `tcpdump icmp` |
| By number | `ip proto <num>` | `tcpdump ip proto 17` |

### 🖥️ Hosts & Networks
| Task | Filter | Example |
|------|--------|---------|
| Single host | `host <ip>` | `tcpdump host 10.0.0.5` |
| Source/Destination host | `src host <ip>` / `dst host <ip>` | `tcpdump src host 192.168.1.10` |
| Subnet | `net <cidr>` | `tcpdump net 192.168.1.0/24` |
| Gateway path | `gateway host <ip>` | `tcpdump gateway host 192.168.1.1` |

### 📦 Packet Characteristics
| Task | Filter | Example |
|------|--------|---------|
| Small packets | `less <len>` | `tcpdump less 64` |
| Large packets | `greater <len>` | `tcpdump greater 1500` |
| SYNs only | `tcp[tcpflags] & tcp-syn != 0` | `tcpdump -nn "tcp[tcpflags] & tcp-syn != 0"` |
| RSTs only | `tcp[tcpflags] & tcp-rst != 0` | `tcpdump -nn "tcp[tcpflags] & tcp-rst != 0"` |

### 📢 Broadcasts, Multicasts, VLAN/MPLS
| Task | Filter | Example |
|------|--------|---------|
| Broadcasts | `(ether|ip) broadcast` | `tcpdump ether broadcast` |
| Multicasts | `(ether|ip|ip6) multicast` | `tcpdump ip multicast` |
| VLAN‑tagged | `vlan [id]` | `tcpdump vlan 100` |
| MPLS | `mpls [label]` | `tcpdump mpls 200` |

### 🧹 Noise Reduction
| Goal | Filter | Example |
|-----|--------|---------|
| Remove DNS | `not port 53` | `tcpdump tcp and not port 53` |
| Remove ARP | `not arp` | `tcpdump not arp` |
| Ignore local subnet | `not net <cidr>` | `tcpdump not net 192.168.1.0/24` |

### 🔀 Combining Filters
- **AND** → both must match: `tcpdump tcp and port 443`  
- **OR** → either can match: `tcpdump port 80 or port 443`  
- **NOT** → exclude traffic: `tcpdump tcp and not port 22`

**Example**
```bash
tcpdump -nn "tcp and port 443 and not src net 192.168.0.0/16"
```

## 🔹 TShark (CLI Wireshark)
TShark is the **command-line interface to Wireshark**, ideal for automation, scripting, and environments without GUI access.

### 🔧 Common Switches
| Switch | Description | Example |
|--------|-------------|---------|
| `-D` | List interfaces | `tshark -D` |
| `-i <int>` | Select interface | `tshark -i eth0` |
| `-c <#>` | Stop after X packets | `tshark -i eth0 -c 100` |
| `-f <filter>` | Capture filter (tcpdump syntax) | `tshark -i eth0 -f "port 80"` |
| `-Y <filter>` | Display filter (Wireshark syntax) | `tshark -r test.pcap -Y "dns"` |
| `-r <file>` | Read from file | `tshark -r test.pcap` |
| `-w <file>` | Write to file | `tshark -i eth0 -w test.pcap` |
| `-T fields` | Print selected fields | `tshark -T fields -e ip.src -e ip.dst` |
| `-z io,stat,<sec>` | Show statistics every interval | `tshark -z io,stat,10` |

### 🔍 Filters
- **Capture filters:** Same as tcpdump (set before capture). Example: `tshark -f "tcp port 443"`  
- **Display filters:** Same as Wireshark GUI (applied after). Example: `tshark -r test.pcap -Y "http.request"`  

### 💡 Use Cases
- **Extract HTTP requests with URI:**
  ```bash
  tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
  ```
- **Find top talkers:**
  ```bash
  tshark -r capture.pcap -T fields -e ip.src | sort | uniq -c | sort -nr
  ```
- **Follow TCP stream in CLI:**
  ```bash
  tshark -r capture.pcap -qz follow,tcp,ascii,1
  ```
- **Extract DNS queries only:**
  ```bash
  tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name
  ```
- **Export HTTP objects:**
  ```bash
  tshark -r capture.pcap --export-objects http,./http_files
  ```

---

## 🔹 Wireshark (GUI)
Wireshark is a **graphical packet analyzer** with deep inspection, stream reassembly, and visualizations.

### 🔧 Capture Filters (tcpdump syntax)
| Filter | Description | Example |
|--------|-------------|---------|
| `host 10.10.10.5` | Single host | `host 10.10.10.5` |
| `net 192.168.1.0/24` | Subnet capture | `net 192.168.1.0/24` |
| `port 80` | HTTP traffic | `port 80` |
| `src host 10.10.10.5` | Source IP | `src host 10.10.10.5` |
| `not port 22` | Exclude SSH | `not port 22` |

### 🔍 Display Filters (Wireshark syntax)
| Filter | Description | Example |
|--------|-------------|---------|
| `ip.addr == 10.10.10.5` | All traffic for one host | — |
| `tcp.port == 21` | FTP traffic | — |
| `dns` | Only DNS queries/responses | — |
| `http && image-jfif` | Show JPEGs transferred | — |
| `tcp.stream eq 3` | Reassemble TCP conversation | — |
| `ftp.request.command` | Show FTP commands | — |
| `http.request.method == "POST"` | Spot uploads/exfil | — |
| `ssl.handshake` | TLS handshake traffic | — |

### 📊 Advanced Features
- **Follow Streams:** Reconstruct conversations (HTTP, FTP, SMTP).  
- **Export Objects:** *File → Export Objects* to extract files (HTTP, SMB).  
- **Statistics Menu:**
  - *Protocol Hierarchy* → % of traffic by protocol  
  - *Conversations* → Who talks to who  
  - *Endpoints* → Top talkers  
  - *I/O Graphs* → Spot spikes or beaconing  
- **Color Rules:** Highlight anomalies (e.g., TCP resets in red).  
- **Expert Info:** Automatic alerts for retransmissions, errors, and anomalies.  

### 💡 Use Cases
- **Detect C2 traffic:** `http.user_agent contains "Mozilla"` (spot odd user agents).  
- **Find exfiltration:** `http.request.method == "POST" && frame.len > 1000`.  
- **Analyze TLS:** Use `ssl.handshake.extensions_server_name` to identify hostnames in encrypted traffic.  

---

## 🔹 Misc Commands
| Command | Description | Example |
|---------|-------------|---------|
| `which <tool>` | Check if tool installed | `which tcpdump` |
| `sudo apt install <tool>` | Install tool | `sudo apt install wireshark` |
| `man <tool>` | Open manual | `man tcpdump` |

---

## 🔹 Common Ports and Protocols
| Port | Protocol | Description |
|------|----------|-------------|
| `20` | FTP-Data | FTP file transfer channel |
| `21` | FTP-Command | FTP command channel |
| `22` | SSH | Secure shell |
| `23` | Telnet | Insecure remote access |
| `25` | SMTP | Email relay |
| `53` | DNS | Name resolution (can be tunneled) |
| `69` | TFTP | Trivial file transfer |
| `80` | HTTP | Web traffic |
| `88` | Kerberos | Authentication |
| `110` | POP3 | Mail retrieval |
| `111` | RPC | Remote procedure calls |
| `115` | SFTP | Secure FTP over SSH |
| `123` | NTP | Time sync (used in DDoS) |
| `137-139` | NetBIOS | File sharing/session services |
| `179` | BGP | Routing exchange |
| `389` | LDAP | Directory services |
| `443` | HTTPS | Encrypted web traffic |
| `445` | SMB | File/printer sharing |

---

## 🔹 Practical Workflow
1. **Capture raw traffic with tcpdump**  
   ```bash
   sudo tcpdump -i eth0 -w suspect.pcap
   ```
2. **Parse and filter artifacts with TShark**  
   ```bash
   tshark -r suspect.pcap -Y "dns" -T fields -e dns.qry.name
   ```
3. **Deep-dive in Wireshark GUI**  
   - Use display filters (`ip.addr == x.x.x.x && http`)  
   - Follow TCP streams for conversations  
   - Export objects for file exfil detection  

---

👉 This upgraded sheet keeps **all original content**, but adds **switches, filters, examples, and workflows** — organized so you can move seamlessly from **capture → filter → analyze**.





---

## 🔢 Common IP Protocol Numbers

| Number | Protocol | Description |
|--------|----------|-------------|
| 1 | ICMP | Internet Control Message Protocol (ping, errors) |
| 2 | IGMP | Internet Group Management Protocol (multicast) |
| 6 | TCP | Transmission Control Protocol |
| 17 | UDP | User Datagram Protocol |
| 41 | IPv6 | IPv6 encapsulation |
| 47 | GRE | Generic Routing Encapsulation |
| 50 | ESP | IPsec Encapsulation Security Payload |
| 51 | AH | IPsec Authentication Header |
| 88 | EIGRP | Cisco EIGRP routing |
| 89 | OSPF | Open Shortest Path First |
| 132 | SCTP | Stream Control Transmission Protocol |

💡 Use with `ip proto <num>` in tcpdump to filter directly, e.g.:  
```bash
tcpdump ip proto 47
```
(captures GRE traffic)
