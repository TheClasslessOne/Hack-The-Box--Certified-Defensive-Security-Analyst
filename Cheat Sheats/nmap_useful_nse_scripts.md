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
