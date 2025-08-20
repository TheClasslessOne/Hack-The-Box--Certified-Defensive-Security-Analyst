# 📑 Table of Contents

- [📘 Linux Essentials — Detailed Command Cheat Sheet](#-linux-essentials--detailed-command-cheat-sheet)
  - 📖 Help & Documentation
  - 📂 Filesystem Basics
  - 📑 Viewing & Paging
  - 🔎 Search & Text Processing
  - 🔐 Ownership & Permissions
  - 🗜️ Archiving & Compression
  - ⚙️ Processes & Jobs
  - 🧭 Services & Logs (systemd)
  - 🌐 Networking
  - 📦 Package Management (Debian/Ubuntu)
  - 🧮 Hardware & System Info
  - 🧰 Environment & Shell
  - 🔁 File Transfer & Sharing
  - 🛠 Practical Workflows

- [🚀 Admin Quick Reference (One‑Liners)](#-admin-quick-reference-one-liners)
- [⌨️ Helpful Keyboard Shortcuts](#️-helpful-keyboard-shortcuts)
- [⚠️ Commands to Use with Care](#️-commands-to-use-with-care)

---

# 📘 Linux Essentials — Detailed Command Cheat Sheet

## 📖 Help & Documentation
| Command | Description | Example |
|--------|-------------|---------|
| `man <tool>` | Open the manual for a command (q=quit, /search, n=next). | `man ls` |
| `<tool> -h/--help` | Show usage and flags quickly. | `ip --help` |
| `apropos <keyword>` | Search man page descriptions for a keyword. | `apropos network` |
| `whatis <tool>` | One‑line description of a command. | `whatis chmod` |
| `type <name>` | Show whether name is a builtin/alias/function/file. | `type cd` |

---

## 📂 Filesystem Basics
| Command | Description | Example |
|--------|-------------|---------|
| `pwd` | Print current working directory. | `pwd` |
| `ls` | List directory contents; `-l` long, `-a` hidden, `-h` human sizes. | `ls -lah /var/log` |
| `cd <dir>` | Change directory (`cd -` to toggle last dir). | `cd /etc` |
| `tree` | Recursive directory listing (install `tree`). | `tree /opt` |
| `mkdir` | Create directory (`-p` parents). | `mkdir -p /tmp/demo/a/b` |
| `touch` | Create empty file / update timestamp. | `touch notes.txt` |
| `cp` | Copy files/dirs (`-r` recursive, `-a` preserve). | `cp -a src/ dst/` |
| `mv` | Move/rename files/dirs. | `mv old.txt new.txt` |
| `rm` | Remove files/dirs (`-r` recursive, `-f` force). | `rm -rf build/` |
| `ln -s` | Create symbolic link. | `ln -s /var/log/syslog /tmp/syslog` |
| `du` | Disk usage by file/dir (`-h`, `-s`). | `du -sh *` |
| `df` | Mounted filesystem free space. | `df -h` |

---

## 📑 Viewing & Paging
| Command | Description | Example |
|--------|-------------|---------|
| `cat` | Concatenate/print files. | `cat README.md` |
| `nl` | Number lines of files. | `nl -ba script.sh` |
| `head` | First lines (default 10). | `head -50 access.log` |
| `tail` | Last lines; `-f` follow. | `tail -f /var/log/syslog` |
| `less` | Pager with search (`/`, `n`, `G`). | `less /etc/services` |
| `column -t` | Align text into columns. | `cat /etc/passwd | column -t -s:` |

---

## 🔎 Search & Text Processing
| Command | Description | Example |
|--------|-------------|---------|
| `find <path> -name` | Find by name/size/time/perm. | `find /var -type f -name "*.log"` |
| `locate <name>` | Indexed search (run `updatedb` first). | `locate sshd_config` |
| `grep -R` | Regex search; `-i` case‑insens., `-n` line no. | `grep -Rin "ERROR" /var/log` |
| `awk` | Field processing / reports. | `awk -F: '{print $1,$3}' /etc/passwd` |
| `sed` | Stream edit (substitute, delete). | `sed -i 's/foo/bar/g' file.txt` |
| `cut` | Extract columns by delimiter. | `cut -d: -f1,7 /etc/passwd` |
| `sort | uniq -c` | Sort and count uniques. | `sort urls.txt | uniq -c | sort -nr` |
| `tr` | Translate/delete characters. | `tr -d '\r' < win.txt > unix.txt` |
| `wc` | Count lines/words/bytes. | `wc -l access.log` |
| `xargs` | Build and run commands from stdin. | `cat list.txt | xargs -I{} cp {} /tmp/` |

---

## 🔐 Ownership & Permissions
| Command | Description | Example |
|--------|-------------|---------|
| `chmod` | Change perms (symbolic or octal). | `chmod 640 file` / `chmod u+rwx,g+rx file` |
| `chown` | Change owner/group. | `chown alice:dev file` |
| `umask` | Default permission mask. | `umask 022` |
| `getfacl/setfacl` | Extended ACLs (if enabled). | `setfacl -m u:bob:r file` |

---

## 🗜️ Archiving & Compression
| Command | Description | Example |
|--------|-------------|---------|
| `tar -czf` | Create gzip tarball. | `tar -czf logs.tgz /var/log` |
| `tar -xzf` | Extract gzip tarball. | `tar -xzf logs.tgz -C /tmp` |
| `zip/unzip` | Zip archives. | `zip -r site.zip public/` |
| `xz`, `gzip`, `bzip2` | Compress single files. | `xz -z bigfile` |

---

## ⚙️ Processes & Jobs
| Command | Description | Example |
|--------|-------------|---------|
| `ps aux` | Snapshot of processes. | `ps aux | grep nginx` |
| `top` / `htop` | Interactive process monitor. | `htop` |
| `nice/renice` | Set/change CPU priority. | `renice -n 10 -p 1234` |
| `kill/killall` | Send signals (TERM/INT/KILL). | `kill -9 1234` |
| `jobs`/`bg`/`fg` | Job control in current shell. | `sleep 100 & ; jobs ; fg %1` |
| `nohup` | Run immune to hangups. | `nohup script.sh &` |
| `timeout` | Run with time limit. | `timeout 30s cmd` |

---

## 🧭 Services & Logs (systemd)
| Command | Description | Example |
|--------|-------------|---------|
| `systemctl status <svc>` | Service status / last logs. | `systemctl status ssh` |
| `systemctl start|stop|restart` | Control a service. | `systemctl restart nginx` |
| `systemctl enable|disable` | Manage autostart. | `systemctl enable ssh` |
| `journalctl -u <svc>` | View service logs. | `journalctl -u ssh -f` |
| `journalctl --since` | Time‑range logs. | `journalctl --since "1 hour ago"` |
| `systemctl list-unit-files` | List unit files & state. | `systemctl list-unit-files | grep enabled` |

---

## 🌐 Networking
| Command | Description | Example |
|--------|-------------|---------|
| `ip addr` / `ip link` | IPs and interfaces. | `ip addr show eth0` |
| `ip route` | Routing table. | `ip route` |
| `ss -tuln` | Listening TCP/UDP sockets. | `ss -tuln` |
| `ping` | Reachability/latency test. | `ping -c 4 1.1.1.1` |
| `traceroute` / `tracepath` | Path to host. | `traceroute example.com` |
| `dig` / `nslookup` | DNS queries. | `dig A example.com +short` |
| `curl` | HTTP(S) transfers, APIs. | `curl -I https://example.com` |
| `wget` | Download files. | `wget https://host/file.tgz` |
| `python3 -m http.server` | Quick file server (cwd). | `python3 -m http.server 8080` |

> 📝 Note: Prefer `ip` and `ss` over deprecated `ifconfig`/`netstat`.

---

## 📦 Package Management (Debian/Ubuntu)
| Command | Description | Example |
|--------|-------------|---------|
| `apt update` | Refresh package lists. | `sudo apt update` |
| `apt install <pkg>` | Install package(s). | `sudo apt install nmap` |
| `apt remove <pkg>` | Remove package (keep config). | `sudo apt remove nginx` |
| `apt purge <pkg>` | Remove incl. config. | `sudo apt purge nginx` |
| `apt upgrade` | Upgrade all packages. | `sudo apt upgrade` |
| `dpkg -i file.deb` | Install local `.deb`. | `sudo dpkg -i tool.deb` |
| `snap install <pkg>` | Install snap (if used). | `sudo snap install code --classic` |

---

## 🧮 Hardware & System Info
| Command | Description | Example |
|--------|-------------|---------|
| `uname -a` | Kernel/system info. | `uname -a` |
| `hostnamectl` | Hostname, OS, kernel. | `hostnamectl` |
| `lsblk -f` | Block devices & filesystems. | `lsblk -f` |
| `lspci` / `lsusb` | PCI / USB devices. | `lspci -v` |
| `free -h` | Memory usage. | `free -h` |
| `uptime` | Load averages & uptime. | `uptime` |
| `dmesg` | Kernel ring buffer. | `dmesg | less` |
| `lsof` | Open files / sockets. | `lsof -i :22` |

---

## 🧰 Environment & Shell
| Command | Description | Example |
|--------|-------------|---------|
| `which` / `command -v` | Locate executables. | `which python3` |
| `echo $VAR` / `export` | Read/set env vars. | `export PATH=$PATH:/opt/bin` |
| `alias` / `unalias` | Shortcuts for commands. | `alias ll='ls -lah'` |
| `history` | Shell history. | `history | tail` |
| `. profile` / `source` | Reload shell config. | `source ~/.bashrc` |

---

## 🔁 File Transfer & Sharing
| Command | Description | Example |
|--------|-------------|---------|
| `scp` | Copy over SSH. | `scp file user@host:/tmp/` |
| `rsync -av` | Sync files/dirs efficiently. | `rsync -av --progress src/ host:/srv/src/` |
| `nc` (netcat) | Simple TCP listener/sender. | `nc -lvp 9001 > out.bin` / `nc host 9001 < in.bin` |
| `sftp` | Interactive SSH file transfer. | `sftp user@host` |

---

## 🛠 Practical Workflows

**1) Find top 10 largest files under /var**  
```bash
sudo du -ah /var 2>/dev/null | sort -h | tail -n 10
```

**2) Recursively replace text in a project**  
```bash
grep -RIl "OldName" . | xargs sed -i 's/OldName/NewName/g'
```

**3) Show processes bound to a port**  
```bash
sudo ss -tulnp | grep ':8080'
```

**4) Follow a service log in real time**  
```bash
journalctl -u nginx -f
```

**5) Create & extract archives**  
```bash
tar -czf backup_$(date +%F).tgz /etc
tar -xzf backup_2025-08-20.tgz -C /restore/path
```

**6) Quick share a directory**  
```bash
cd ~/Downloads && python3 -m http.server 8000
# then: curl -O http://<your-ip>:8000/file
```

**7) Copy a directory to a remote server**  
```bash
rsync -av --progress ./site/ user@host:/var/www/site/
```

---

# 🚀 Admin Quick Reference (One‑Liners)

- **Open ports + owning processes**: `sudo ss -tulnp`  
- **Top memory hogs**: `ps aux --sort -rss | head`  
- **Top CPU hogs**: `ps aux --sort -%cpu | head`  
- **Disk space by dir**: `sudo du -xh / | sort -h | tail -n 20`  
- **Who/where**: `w` / `last -a | head`  
- **Network info quick**: `ip -brief addr ; ip route`  

---

# ⌨️ Helpful Keyboard Shortcuts

- **Ctrl+C** stop | **Ctrl+Z** suspend | **fg/bg** resume  
- **Ctrl+A/E** start/end of line | **Alt+B/F** prev/next word  
- **Ctrl+R** reverse-search history | **!!** repeat last command  
- **Tab** completion | **Ctrl+L** clear screen  

---

# ⚠️ Commands to Use with Care

- `rm -rf /path` — irreversible delete (double‑check target).  
- `chmod -R 777` — grants world write/execute; avoid on system dirs.  
- `kill -9 <pid>` — hard kill; may cause data loss (try `TERM` first).  
- `curl | sh` — piping to shell is risky; review scripts first.  

---
