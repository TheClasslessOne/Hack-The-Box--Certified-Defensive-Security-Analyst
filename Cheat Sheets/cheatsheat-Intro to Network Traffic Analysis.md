# 🛡️ Network Traffic Analysis Cheat Sheet

⚠️ Unless you are running as root, `sudo` privileges are required for packet capture tools since they must set interfaces into **promiscuous mode** or bind to them.

---

## 🔹 Nomachine Connection Information
For HTB Academy labs or similar training environments.
- **Target IP:** 10.129.43.4  
- **Username:** htb-student  
- **Password:** HTB_@cademy_stdnt!

---

## 🔹 Tcpdump (CLI Packet Capture)
Tcpdump is lightweight and fast — perfect for quick captures, filtering, and creating `.pcap` files for deeper analysis in Wireshark.

### 🔧 Common Switches
| Switch | Description | Example |
|--------|-------------|---------|
| `-D` | List available interfaces | `tcpdump -D` |
| `-i` | Select interface | `tcpdump -i eth0` |
| `-n` | Don’t resolve hostnames | `tcpdump -n` |
| `-nn` | Don’t resolve hostnames/ports | `tcpdump -nn` |
| `-e` | Include Ethernet header | `tcpdump -e -i eth0` |
| `-X` | Show packets in hex + ASCII | `tcpdump -X -i eth0` |
| `-XX` | Hex + ASCII + Ethernet header | `tcpdump -XX -i eth0` |
| `-v/-vv/-vvv` | Increase verbosity | `tcpdump -vv -i eth0` |
| `-c <#>` | Capture X packets then exit | `tcpdump -c 50 -i eth0` |
| `-s <#>` | Set snapshot length (bytes) | `tcpdump -s 0 -i eth0` (0 = full packet) |
| `-S` | Show absolute TCP sequence numbers | `tcpdump -S -i eth0` |
| `-q` | Print less protocol info | `tcpdump -q -i eth0` |
| `-w <file>` | Write to file | `tcpdump -w test.pcap -i eth0` |
| `-r <file>` | Read from file | `tcpdump -r test.pcap` |

### 🔍 Filters
| Filter | Description | Example |
|--------|-------------|---------|
| `host <ip>` | Filter by host IP | `tcpdump host 10.10.10.5` |
| `src host <ip>` | Filter by source IP | `tcpdump src host 192.168.1.10` |
| `dst host <ip>` | Filter by destination IP | `tcpdump dst host 192.168.1.10` |
| `port <#>` | Filter by port | `tcpdump port 80` |
| `src port <#>` | Filter by source port | `tcpdump src port 22` |
| `dst port <#>` | Filter by destination port | `tcpdump dst port 53` |
| `net <subnet>` | Filter by network | `tcpdump net 192.168.1.0/24` |
| `tcp / udp / icmp` | Protocol-based filter | `tcpdump icmp` |
| `portrange X-Y` | Filter port range | `tcpdump portrange 20-25` |
| `and` | Logical AND | `tcpdump host 10.10.10.5 and port 22` |
| `or` | Logical OR | `tcpdump port 80 or port 443` |
| `not` | Negation | `tcpdump not port 22` |

### 💡 Use Cases
- **Detect beaconing malware:** `tcpdump -i eth0 dst port 80 or 443`  
- **Sniff credentials (lab use only):** `tcpdump -A -i eth0 port 21 or port 23`  
- **Detect tunneling:** `tcpdump -i eth0 icmp`  

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
