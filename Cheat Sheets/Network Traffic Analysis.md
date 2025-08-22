# 🛡️ Network Traffic Analysis Cheat Sheet


⚠️ Unless you are running as root, `sudo` privileges are required for packet capture tools since they must set interfaces into **promiscuous mode** or bind to them.


## 🔹 Tcpdump (CLI Packet Capture)
Tcpdump is lightweight and fast — perfect for quick captures, filtering, and creating `.pcap` files for deeper analysis in Wireshark.


### 🔧 Command Line Options
| Option | Description | Example |
|--------|-------------|---------|
| `-A` | Print frame payload in ASCII | `tcpdump -A -i eth0` |
| `-c <count>` | Exit after capturing count packets | `tcpdump -c 50 -i eth0` |
| `-D` | List available interfaces | `tcpdump -D` |
| `-e` | Print link-level headers | `tcpdump -e -i eth0` |
| `-F <file>` | Use file as filter expression | `tcpdump -F filter.txt` |
| `-G <n>` | Rotate dump file every n seconds | `tcpdump -G 60 -w capture-%Y-%m-%d_%H-%M-%S.pcap` |
| `-i <iface>` | Capture on interface | `tcpdump -i eth0` |
| `-K` | Don’t verify TCP checksums | `tcpdump -K -i eth0` |
| `-L` | List data link types for the interface | `tcpdump -i eth0 -L` |
| `-n` | Don’t resolve hostnames | `tcpdump -n -i eth0` |
| `-nn` | Don’t resolve hostnames or ports | `tcpdump -nn -i eth0` |
| `-p` | Don’t capture in promiscuous mode | `tcpdump -p -i eth0` |
| `-q` | Quick output (less detail) | `tcpdump -q -i eth0` |
| `-r <file>` | Read from file | `tcpdump -r test.pcap` |
| `-s <len>` | Capture up to len bytes | `tcpdump -s 0 -i eth0` |
| `-S` | Show absolute TCP sequence numbers | `tcpdump -S -i eth0` |
| `-t` | Don’t print timestamps | `tcpdump -t -i eth0` |
| `-v, -vv, -vvv` | Increase verbosity | `tcpdump -vvv -i eth0` |
| `-w <file>` | Write packets to file | `tcpdump -w out.pcap -i eth0` |
| `-x` | Print payload in hex | `tcpdump -x -i eth0` |
| `-X` | Print payload in hex + ASCII | `tcpdump -X -i eth0` |
| `-y <type>` | Specify data link type | `tcpdump -y EN10MB -i eth0` |
| `-Z <user>` | Drop privileges to user | `tcpdump -Z nobody -i eth0` |


## 🔍 Tcpdump Capture Filter Primitives (Cheat Sheet)

### 🎯 Host & Network
| Filter | Purpose | Example | When to Use |
|--------|---------|---------|-------------|
| `src host <ip>` / `dst host <ip>` | Match packets from/to an IP | `tcpdump src host 10.0.0.1` | Narrow down to traffic from a single machine |
| `ether src host <mac>` / `ether dst host <mac>` | Match packets from/to a MAC | `tcpdump ether src host 00:11:22:33:44:55` | Useful when devices share IPs (DHCP, ARP issues) |
| `gateway host <ip>` | Match traffic going through a gateway | `tcpdump gateway host 192.168.1.1` | Check routing or gateway bottlenecks |
| `net <network>/<mask>` | Match subnet traffic | `tcpdump net 192.168.1.0/24` | Capture everything inside a subnet |

---

### 🔌 Ports
| Filter | Purpose | Example | When to Use |
|--------|---------|---------|-------------|
| `tcp src port <p>` / `udp dst port <p>` | Match specific TCP/UDP port | `tcpdump tcp dst port 80` | Troubleshoot web traffic, DNS queries, etc. |
| `tcp portrange <p1>-<p2>` / `udp portrange <p1>-<p2>` | Match range of ports | `tcpdump udp portrange 5000-6000` | Capture ephemeral ports or service ranges |

---

### 📦 Packet Size
| Filter | Purpose | Example | When to Use |
|--------|---------|---------|-------------|
| `less <len>` | Capture packets ≤ length | `tcpdump less 64` | Spot small packets (pings, SYNs, scans) |
| `greater <len>` | Capture packets ≥ length | `tcpdump greater 1500` | Find jumbo frames or oversized packets |

---

### 📡 Protocols & Types
| Filter | Purpose | Example | When to Use |
|--------|---------|---------|-------------|
| `(ether|ip|ip6) proto <num>` | Match by protocol number | `tcpdump ip proto 6` (TCP) | Debug specific protocols (e.g., ICMP = 1, TCP = 6, UDP = 17) |
| `(ether|ip) broadcast` | Match broadcasts | `tcpdump ether broadcast` | Diagnose ARP storms, DHCP discover, broadcast noise |
| `(ether|ip|ip6) multicast` | Match multicasts | `tcpdump ip multicast` | Check multicast routing or streaming apps |
| `type (mgt|ctl|data)` | Match 802.11 Wi-Fi frame type | `tcpdump type ctl` | Wi-Fi troubleshooting at frame-level |
| `vlan [id]` | Capture VLAN-tagged traffic | `tcpdump vlan 100` | Verify VLAN tagging/trunk links |
| `mpls [label]` | Capture MPLS traffic | `tcpdump mpls 200` | MPLS-specific debugging in WAN environments |



### 🔗 Protocols
- `arp, ether, fddi, icmp, ip, ip6, link, ppp, radio, rarp, slip, tcp, tr, udp, wlan`


### 🚩 TCP Flags
- `tcp-urg, tcp-ack, tcp-psh, tcp-rst, tcp-syn, tcp-fin`


### 🌐 ICMP Types
- `icmp-echoreply, icmp-unreach, icmp-sourcequench, icmp-redirect, icmp-echo, icmp-routeradvert, icmp-routersolicit, icmp-timxceed, icmp-paramprob, icmp-tstamp, icmp-tstampreply, icmp-ireq, icmp-ireqreply, icmp-maskreq, icmp-maskreply`


### ➕ Modifiers
- `! or not` → Negation
- `&& or and` → Logical AND
- `|| or or` → Logical OR


### 💡 Example Filters
| Example | Description |
- **Detect SYN flood:** `tcpdump -nni eth0 'tcp[tcpflags] & tcp-syn != 0'`

# 🕵️ Tcpdump Review Filters (PCAP Analysis Cheat Sheet)

## 🔌 Ports & Services
| Task | Filter | Example |
|------|--------|---------|
| Show traffic on a single port | `port <p>` | `tcpdump port 80` |
| Show TCP traffic to/from a port | `tcp dst port <p>` / `tcp src port <p>` | `tcpdump tcp dst port 443` |
| Show UDP traffic to/from a port | `udp dst port <p>` / `udp src port <p>` | `tcpdump udp src port 53` |
| Show range of ports | `portrange <p1>-<p2>` | `tcpdump portrange 1024-65535` |

---

## 📡 Protocols
| Task | Filter | Example |
|------|--------|---------|
| Only TCP | `tcp` | `tcpdump tcp` |
| Only UDP | `udp` | `tcpdump udp` |
| Only ICMP | `icmp` | `tcpdump icmp` |
| Match protocol by number | `ip proto <num>` | `tcpdump ip proto 6` (TCP), `tcpdump ip proto 17` (UDP) |

---

## 🖥️ Hosts & Networks
| Task | Filter | Example |
|------|--------|---------|
| Traffic from/to single host | `host <ip>` | `tcpdump host 10.0.0.5` |
| Only source/destination host | `src host <ip>` / `dst host <ip>` | `tcpdump src host 192.168.1.10` |
| Subnet traffic | `net <subnet>/<mask>` | `tcpdump net 192.168.1.0/24` |
| Gateway traffic | `gateway host <ip>` | `tcpdump gateway host 192.168.1.1` |

---

## 📦 Packet Characteristics
| Task | Filter | Example |
|------|--------|---------|
| Small packets (scans, pings) | `less <len>` | `tcpdump less 64` |
| Large packets (jumbo frames) | `greater <len>` | `tcpdump greater 1500` |
| Capture only SYN packets | `'tcp[tcpflags] & tcp-syn != 0'` | `tcpdump 'tcp[tcpflags] & tcp-syn != 0'` |
| Capture only RST packets | `'tcp[tcpflags] & tcp-rst != 0'` | `tcpdump 'tcp[tcpflags] & tcp-rst != 0'` |

---

## 📢 Broadcasts, Multicasts, VLANs
| Task | Filter | Example |
|------|--------|---------|
| Broadcast packets | `(ether|ip) broadcast` | `tcpdump ether broadcast` |
| Multicast packets | `(ether|ip|ip6) multicast` | `tcpdump ip multicast` |
| VLAN-tagged traffic | `vlan [id]` | `tcpdump vlan 100` |
| MPLS traffic | `mpls [label]` | `tcpdump mpls 200` |

---

## 🧹 Noise Reduction
| Task | Filter | Example |
|------|--------|---------|
| Ignore DNS chatter | `not port 53` | `tcpdump tcp and not port 53` |
| Ignore ARP packets | `not arp` | `tcpdump not arp` |
| Ignore local subnet traffic | `not net <subnet>` | `tcpdump not net 192.168.1.0/24` |

---

## 🔀 Combining Filters
- **AND** → both must match  
  `tcpdump tcp and port 443`
- **OR** → either can match  
  `tcpdump port 80 or port 443`
- **NOT** → exclude traffic  
  `tcpdump tcp and not port 22`

### Example:  
```bash
tcpdump tcp and port 443 and not src net 192.168.0.0/16


---

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



