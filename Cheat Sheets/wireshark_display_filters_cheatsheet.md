# Wireshark Display Filter Cheat Sheet (HTB-CDSA Focus)

A practical, “teach-while-you-do” list of **Wireshark display filters** you’ll actually use in HTB labs and blue-team work. Each filter includes a **plain-English** explanation and, where useful, a **tshark** example for counting.

> **How to use:** Paste a filter into Wireshark’s *Display Filter* bar and press **Enter**. To get the **total count**, look at the bottom status bar (`Displayed: X`) or use **Statistics → Summary** after applying the filter.  
> **tshark counting pattern:** `tshark -r file.pcap -Y '<filter>' | wc -l`

---

## 0) Capture vs Display Filters (Quick Primer)
- **Display filters (this sheet):** non-destructive; you can stack logic (`&&`, `||`, `!`), works on decoded protocol fields (e.g., `http.host`).  
- **Capture filters (`BPF`):** set *before* capture (e.g., `tcp port 80`). Faster, but less expressive.

---

## 1) Essentials (IP, MAC, Ports)

```wireshark
ip.addr == 10.10.10.10              # Any packet where either src or dst IP is 10.10.10.10
ip.src == 10.10.10.5                # Only packets *from* 10.10.10.5
ip.dst == 10.10.10.1                # Only packets *to* 10.10.10.1
eth.src == aa:bb:cc:dd:ee:ff        # Source MAC (Ethernet)
eth.dst == ff:ff:ff:ff:ff:ff        # Broadcast frames
tcp.port == 80                      # Either TCP src or dst port is 80
udp.port == 53                      # Either UDP src or dst port is 53
frame.len > 1400                    # Jumbo/fragment-sized frames
frame contains "flag{"
```

**Tips**
- Combine IP + port: `ip.addr == 10.10.10.5 && tcp.port == 22`
- Negate: `!(dns) && !(arp)` to hide noise.

---

## 2) ARP (Conflicts, Poisoning)

```wireshark
arp                                   # All ARP
arp.opcode == 1                       # ARP Request (“Who has … ?”)
arp.opcode == 2                       # ARP Reply (“… is at …”)
arp.opcode == 1 && eth.src == 08:00:27:53:0c:ba   # Requests from a specific MAC
arp.src.proto_ipv4 == 192.168.10.4    # Replies claiming "I am 192.168.10.4"
```

**Use-cases**
- **IP conflict:** Multiple different `eth.src` claiming same `arp.src.proto_ipv4`.  
- **Count ARP requests “from MAC X”**: apply filter, read **Displayed** bottom bar.

---

## 3) ICMP (Pings, Floods)

```wireshark
icmp                                  # All ICMP
icmp.type == 8                        # Echo Request
icmp.type == 0                        # Echo Reply
icmp && ip.src == 192.168.10.5 && ip.dst == 192.168.10.1     # Attacker → Victim
```

**Fragmented ping floods:** You’ll see many `IPv4 Fragmented IP protocol (proto=ICMP)` plus periodic reassembled `Echo (ping) request` lines. Filter `icmp` to view just the reassembled requests/replies.

---

## 4) TCP Flags & Handshakes

```wireshark
tcp                                   # All TCP
tcp.flags.syn == 1 && tcp.flags.ack == 0   # Initial SYNs (handshake starts)
tcp.flags.syn == 1 && tcp.flags.ack == 1   # SYN/ACK (server)
tcp.flags.fin == 1                    # FIN set
tcp.flags.reset == 1                  # RST set
tcp.flags.ack == 1                    # ACK set (any packet acknowledging data)
tcp.analysis.retransmission           # Detected retransmissions
tcp.analysis.flags                    # Any TCP analysis issue (OOO, dup ack, etc.)
tcp.window_size_value == 0            # Zero window (receiver overwhelmed)
tcp.len > 0                           # TCP segments that carry payload
```

**ACK-only packets** (no SYN/FIN/RST/PSH/URG):
```wireshark
tcp.flags.ack == 1 && tcp.flags.syn == 0 && tcp.flags.fin == 0 && tcp.flags.reset == 0 && tcp.flags.push == 0 && tcp.flags.urg == 0
```

---

## 5) HTTP / Web

```wireshark
http                                  # Any HTTP parsed
http.request                          # All HTTP requests
http.request.method == "GET"          # GETs only
http.request.method == "POST"         # POSTs only
http.request.method == "GET" && tcp.port == 80     # GETs on port 80
http.host == "inlanefreight.com"      # Host header filter
http.request.uri contains "/admin"    # Path contains
http.response.code == 404             # 404s
http.user_agent contains "curl"       # User-Agent contains “curl”
```

**Export objects:** `File → Export Objects → HTTP` to pull binaries, images, etc.

---

## 6) TLS / HTTPS

```wireshark
tls                                   # All TLS
tls.handshake                         # TLS handshakes
tls.handshake.type == 1               # ClientHello
tls.handshake.type == 2               # ServerHello
tls.record.version == 0x0303          # TLS 1.2 records
tls.handshake.extensions_server_name == "example.com"  # SNI hostname
```

> You can still see metadata (SNI, certs, ciphers) even if payload is encrypted.

---

## 7) DNS (Resolutions, Tunnels)

```wireshark
dns                                   # All DNS
dns.flags.response == 0               # DNS queries
dns.flags.response == 1               # DNS responses
dns.qry.name == "example.com"         # Exact FQDN
dns.qry.name contains "example"       # Contains substring
dns.a                                   # Any A records in responses
dns.ptr                                # Reverse lookups
udp.port == 53 || tcp.port == 53       # DNS over UDP/TCP
```

**Suspicious signs:** Many long TXT queries or high-rate queries to one domain → possible tunneling.

---

## 8) DHCP (Addressing Issues)

```wireshark
bootp                                 # DHCP (legacy name)
bootp.option.dhcp == 3                # DHCP Request
bootp.option.dhcp == 2                # DHCP Offer
```

---

## 9) Wi-Fi (802.11) – Evil Twin / Deauth / SSIDs

```wireshark
wlan                                   # All 802.11
wlan.fc.type_subtype == 8              # Beacon frames (APs advertising SSID)
wlan_mgt.ssid == "CoffeeShopWiFi"      # Specific SSID
wlan.fc.type_subtype == 12             # Deauthentication frames
wlan.ta                                # Transmitter address (MAC sending the frame)
wlan.ra                                # Receiver address (client being targeted)
```

**Count unique attackers (deauth senders) – tshark:**
```bash
tshark -r rogueap.cap -Y "wlan.fc.type_subtype==12" -T fields -e wlan.ta | sort -u | wc -l
```

**Find the victim (most deauthed receiver):**
```bash
tshark -r rogueap.cap -Y "wlan.fc.type_subtype==12" -T fields -e wlan.ra | sort | uniq -c | sort -nr | head
```

---

## 10) Files, Credentials, Indicators

```wireshark
frame contains "password="             # Cleartext creds in HTTP/FTP forms
ftp || ftp-data                        # FTP control/data
smtp || pop || imap                    # Mail protocols (legacy)
ntlmssp                                # NTLM authentication sequences
kerberos                               # Kerberos tickets
```

> Use **Follow → TCP Stream** to reconstruct conversations; **Export Objects** to extract files.

---

## 11) Performance & Troubleshooting

```wireshark
tcp.analysis.retransmission            # Packet loss symptoms
tcp.analysis.out_of_order              # Reordering
icmp.type == 3                         # Destination unreachable
tcp.time_delta > 1                     # Gaps > 1s between TCP packets (slow)
tcp.stream eq 7                        # Only stream #7 (right-click any packet → Follow Stream to find its id)
```

---

## 12) Security Signals & Suspicions

```wireshark
arp && arp.src.proto_ipv4 == 192.168.10.4 && eth.src != 08:00:27:53:0c:ba
# Someone else claiming to be 192.168.10.4 (IP conflict/poison)

dns && (dns.qry.name contains ".onion" || dns.qry.name contains ".bit")
# Odd TLDs

http && (http.request.uri contains ".php?cmd=" || http.cookie contains "PHPSESSID")
# Webshell-ish patterns / session abuse

tcp.flags.reset == 1 && tcp.len == 0
# Pure RSTs (port scans or kill connections)
```

---

## 13) Counting Quickly (GUI & CLI)

- **GUI:** Apply a filter → bottom status bar shows `Displayed: X`.  
- **Endpoints/Conversations:** **Statistics → Endpoints** or **Conversations** after filtering to aggregate by IP/MAC/port.  
- **tshark count:**  
  ```bash
  tshark -r file.pcap -Y '<filter>' | wc -l
  ```

**Examples**
```bash
# Count HTTP GET to port 80
tshark -r cap.pcap -Y 'http.request.method == "GET" && tcp.port == 80' | wc -l

# Count TCP RSTs
tshark -r cap.pcap -Y 'tcp.flags.reset==1' | wc -l

# Count ACK-flagged packets
tshark -r cap.pcap -Y 'tcp.flags.ack==1' | wc -l
```

---

## 14) Common Pitfalls

- **No dissector?** If traffic is on a non-standard port (e.g., HTTP on 8081), add it: **Analyze → Decode As…**.  
- **Encrypted doesn’t mean invisible:** You still get metadata (SNI, certs, DNS, JA3).  
- **Filter order matters:** `&&` (AND) binds tighter than `||` (OR); use parentheses if unsure.  
- **Don’t confuse capture vs display filters:** This sheet is for **display filters**.

---

## 15) Mini-Playbooks

**Find first MAC that claimed an IP (ARP Reply):**
```wireshark
arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1
# Topmost packet (earliest) → check "arp.src.hw_mac" or "eth.src"
```

**Only HTTP requests to victim over cleartext:**
```wireshark
http.request && ip.dst == 192.168.10.1 && tcp.port == 80
```

**SSL/TLS SNI for a suspect host:**
```wireshark
tls.handshake.extensions_server_name == "evil.example"
```

---

### Keep Building Muscle Memory
When in doubt: **Right-click → Apply as Filter → Selected** from the field you care about. Wireshark will write the filter for you, and you can learn the syntax by example.

---

*Made for HTB CDSA prep — concise, actionable, and field-tested.*
