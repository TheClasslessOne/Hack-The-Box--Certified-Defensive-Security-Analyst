# 🐧 Linux Fundamentals — Detailed Cheat Sheet

## 📚 Getting Help
| Command | Description | Example |
|---------|-------------|---------|
| `man <tool>` | Show manual page. | `man ls` |
| `<tool> -h` | Show help. | `ls -h` |
| `apropos <keyword>` | Search man pages. | `apropos network` |

---

## 👤 User & Identity
| Command | Description | Example |
|---------|-------------|---------|
| `whoami` | Current user. | |
| `id` | User identity + groups. | |
| `hostname` | Show system hostname. | |
| `uname -a` | Kernel + OS info. | |
| `pwd` | Show working dir. | |

---

## 🌐 Networking
| Command | Description | Example |
|---------|-------------|---------|
| `ifconfig` | Interface config (deprecated, use `ip`). | |
| `ip a` | Show interfaces. | |
| `ip route` | Show routing table. | |
| `ss -tulpn` | List sockets. | |
| `netstat -an` | Legacy connections view. | |

---

## 🗂 Filesystem
| Command | Description | Example |
|---------|-------------|---------|
| `ls -la` | List files w/ perms. | |
| `cd /etc` | Change dir. | |
| `touch file.txt` | Create file. | |
| `mkdir newdir` | Make dir. | |
| `tree` | Recursive view. | |
| `cp a b` | Copy file. | |
| `mv a b` | Move/rename file. | |
| `rm file` | Delete file. | |

---

## 🔍 Finding Files
| Command | Description | Example |
|---------|-------------|---------|
| `which python3` | Find binary. | |
| `find / -name "*.conf"` | Search files. | |
| `locate passwd` | Use DB to find file. | |
| `updatedb` | Update locate DB. | |

---

## 📑 Viewing Files
| Command | Description | Example |
|---------|-------------|---------|
| `cat file` | Print file. | |
| `less file` | Scroll file. | |
| `head -n 20 file` | First 20 lines. | |
| `tail -f log.txt` | Follow log. | |
| `wc -l file` | Count lines. | |

---

## 🔧 Text Processing
| Command | Description | Example |
|---------|-------------|---------|
| `grep "root" /etc/passwd` | Search pattern. | |
| `sort file` | Sort file. | |
| `cut -d: -f1 /etc/passwd` | Split lines. | |
| `awk '{print $1}' file` | Field print. | |
| `sed 's/foo/bar/g' file` | Replace text. | |

---

## 👥 User Management
| Command | Description | Example |
|---------|-------------|---------|
| `sudo <cmd>` | Run as root. | |
| `su - user` | Switch user. | |
| `useradd bob` | Add user. | |
| `usermod -aG sudo bob` | Add to group. | |
| `passwd bob` | Change pw. | |
| `delgroup group` | Remove group. | |

---

## 📦 Package Management
| Tool | Command | Example |
|------|---------|---------|
| Debian | `apt install curl` | |
| Debian | `dpkg -i pkg.deb` | |
| RHEL | `yum install nmap` | |
| RHEL | `rpm -i pkg.rpm` | |
| Universal | `snap install app` | |
| Python | `pip install requests` | |
| Ruby | `gem install rails` | |

---

## ⚙️ Processes & Services
| Command | Description | Example |
|---------|-------------|---------|
| `ps aux` | Show all processes. | |
| `kill -9 PID` | Kill process. | |
| `jobs` | List background jobs. | |
| `fg %1` | Resume job. | |
| `systemctl status ssh` | Show service status. | |
| `journalctl -u ssh` | Show logs for service. | |

---

## 🌍 Networking Tools
| Command | Description | Example |
|---------|-------------|---------|
| `curl http://site` | Fetch page. | |
| `wget file.zip` | Download file. | |
| `python3 -m http.server 8080` | Simple web server. | |

---

## 🔐 Permissions
| Command | Description | Example |
|---------|-------------|---------|
| `chmod 755 file` | Set permissions. | |
| `chown user:group file` | Change ownership. | |
