# 🪟 Windows Command Line — Detailed Cheat Sheet

## 🔑 Admin & Remote Access
| Command | Description | Example |
|---------|-------------|---------|
| `xfreerdp /v:<target IP> /u:<user> /p:<password>` | Connect to a host via RDP. | `xfreerdp /v:10.10.10.5 /u:admin /p:Passw0rd!` |
| `ssh <user>@<target>` | Connect via SSH. | `ssh student@192.168.1.10` |
| `<PIPE>` | Represents the pipe key (`Shift+\`). | `dir \| more` |

---

## ⚙️ General Commands
| Command | Description | Example |
|---------|-------------|---------|
| `help <command>` | Show command help. | `help dir` |
| `Get-Help <cmdlet>` | PowerShell help. | `Get-Help Get-Process` |
| `Update-Help` | Download updated help files. | |
| `CTRL+C` | Stop running process. | |
| `Get-Module` | List loaded modules. | |
| `Import-Module` | Load a module. | `Import-Module ActiveDirectory` |
| `Get-Command` | List commands, functions, aliases. | |
| `Set-Location <path>` | Change directory (like `cd`). | `Set-Location C:\Windows` |
| `Get-Content <file>` | Print file contents. | `Get-Content users.txt` |
| `systeminfo` | OS/system info. | |
| `hostname` | Show current hostname. | |
| `ver` | Show Windows version. | |

---

## 📜 Terminal History
| Key/Command | Description |
|-------------|-------------|
| `doskey /history` | Show all commands from session. |
| `↑/↓` | Scroll through history. |
| `F7` | Interactive history menu. |
| `F9` | Run history command by number. |

---

## 📂 File & Directory Management
### CMD
| Command | Description | Example |
|---------|-------------|---------|
| `dir` | List directory contents. | |
| `dir /A:H` | Show hidden files. | |
| `cd <path>` | Change directory. | `cd C:\Users` |
| `tree /F` | Show directory tree with files. | |
| `cls` | Clear screen. | |
| `mkdir <dir>` | Create directory. | |
| `rmdir /S <dir>` | Remove folder + contents. | |
| `copy src dest` | Copy file(s). | |
| `robocopy src dest /MIR` | Mirror directories. | |
| `type <file>` | Show file contents. | |
| `echo text > file.txt` | Write to file. | |
| `echo text >> file.txt` | Append to file. | |
| `del file.txt` | Delete file. | |

### PowerShell
| Command | Alias | Description | Example |
|---------|-------|-------------|---------|
| `Get-ChildItem` | `ls` | List items. | `ls C:\` |
| `New-Item` | `ni` | Create file/folder. | `ni -Name notes.txt -ItemType File` |
| `Copy-Item` | `cp` | Copy object. | |
| `Rename-Item` | `mv` | Rename object. | |
| `Remove-Item` | `rm` | Delete object. | |
| `Get-Content` | `cat` | Show file content. | |
| `Add-Content` | `ac` | Append to file. | |
| `Set-Content` | `sc` | Overwrite file. | |

---

## 🔍 Find & Filter Content
### CMD
| Command | Description | Example |
|---------|-------------|---------|
| `where notepad.exe` | Find file path. | |
| `find "admin" file.txt` | Search for text. | |
| `findstr /i password *.txt` | Search recursively. | |

### PowerShell
| Command | Description | Example |
|---------|-------------|---------|
| `Get-Item \| Get-Member` | Show object properties. | |
| `Get-ChildItem -Recurse \| where {$_.Name -like "*.txt"}` | Find files. | |
| `Select-String -Path *.log -Pattern "error"` | Search logs for errors. | |

---

## 👤 User Management
| Tool | Command | Description |
|------|---------|-------------|
| CMD | `whoami /priv` | Show privileges. |
| CMD | `net user` | List users. |
| PS | `Get-LocalUser` | Show local users. |
| PS | `New-LocalUser` | Create user. |
| PS | `Get-ADUser` | Query AD users. |

---

## 🌐 Networking
| Tool | Command | Description |
|------|---------|-------------|
| CMD | `ipconfig /all` | Show all network settings. |
| CMD | `arp -a` | Show ARP cache. |
| CMD | `netstat -an` | List connections. |
| PS | `Get-NetIPAddress` | Show IP info. |
| PS | `Test-NetConnection` | Test network. |
| PS | `Enter-PSSession -ComputerName host -Credential user` | Remote session. |

---

## 🛠 Services & Tasks
| Tool | Command | Description |
|------|---------|-------------|
| CMD | `sc query` | List services. |
| CMD | `tasklist /svc` | Services + PIDs. |
| PS | `Get-Service` | Show services. |
| CMD | `schtasks /query` | List scheduled tasks. |
| CMD | `schtasks /create /sc daily /tn backup /tr C:\backup.bat` | Create scheduled task. |

---

## 🗝 Registry & Event Logs
| Command | Description |
|---------|-------------|
| `reg query HKLM\Software` | Query registry. |
| `REG ADD HKCU\Software\Test /v Key /t REG_SZ /d Value` | Add key. |
| `wevtutil el` | List all logs. |
| `Get-WinEvent -LogName Security -MaxEvents 5` | Show last 5 security events. |

---

## 💻 PowerShell Scripting
| Concept | Example |
|---------|---------|
| Variables | `$var = "hello"` |
| Functions | `function hi { Write-Output "Hello" }` |
| Comments | `# single line` or `<# multi-line #>` |
| Module Manifest | `New-ModuleManifest .\mymodule.psd1` |
