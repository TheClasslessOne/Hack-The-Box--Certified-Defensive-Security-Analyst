# 📑 Table of Contents

-   [📘 Linux Essentials --- Detailed Command Cheat
    Sheet](#-linux-essentials--detailed-command-cheat-sheet)
    -   📖 Help & Documentation
    -   👤 User & System Identity
    -   📂 File & Directory Management
    -   📑 Text Viewing & Editing
    -   🔎 Search & Processing
    -   💻 System Information
    -   🌐 Networking
    -   ⚙️ Processes & Job Control
    -   🧑‍🤝‍🧑 Users & Permissions
    -   📦 Package Management
    -   🛠 Practical Workflows

------------------------------------------------------------------------

# 📘 Linux Essentials --- Detailed Command Cheat Sheet

## 📖 Help & Documentation

  ------------------------------------------------------------------------
  Command               Description                   Example
  --------------------- ----------------------------- --------------------
  `man <tool>`          Opens the manual page for a   `man ls`
                        command.                      

  `<tool> -h` or        Prints a help page with       `ls --help`
  `--help`              usage/flags.                  

  `apropos <keyword>`   Searches man pages for a      `apropos network`
                        keyword.                      
  ------------------------------------------------------------------------

------------------------------------------------------------------------

## 👤 User & System Identity

  ----------------------------------------------------------------------------------------
  Command              Description                   Example
  -------------------- ----------------------------- -------------------------------------
  `whoami`             Prints current username.      `whoami`

  `id`                 Shows UID, GID, groups.       `id user`

  `hostname`           Prints/sets hostname.         `hostnamectl set-hostname server01`

  `uname`              Displays OS/kernel info.      `uname -a`

  `who`                Lists logged-in users.        `who`

  `env`                Prints environment variables. `env | grep PATH`
  ----------------------------------------------------------------------------------------

------------------------------------------------------------------------

## 📂 File & Directory Management

  Command   Description                    Example
  --------- ------------------------------ ----------------------
  `pwd`     Prints working directory.      `pwd`
  `ls`      Lists directory contents.      `ls -la`
  `cd`      Change directory.              `cd /etc`
  `tree`    Recursive directory listing.   `tree /var/log`
  `touch`   Creates empty file.            `touch notes.txt`
  `mkdir`   Creates directory.             `mkdir -p /tmp/test`
  `cp`      Copies files/directories.      `cp -r dir1 dir2`
  `mv`      Moves/renames files.           `mv file1 file2`
  `rm`      Deletes files/directories.     `rm -rf dir/`

------------------------------------------------------------------------

## 📑 Text Viewing & Editing

  Command   Description                    Example
  --------- ------------------------------ ---------------------
  `cat`     Concatenate & display files.   `cat file.txt`
  `more`    Basic pager for text.          `cat file | more`
  `less`    Enhanced pager with search.    `less /etc/passwd`
  `head`    First 10 lines of file.        `head -20 file.txt`
  `tail`    Last 10 lines of file.         `tail -f logs.txt`
  `nano`    Simple terminal text editor.   `nano script.sh`

------------------------------------------------------------------------

## 🔎 Search & Processing

  --------------------------------------------------------------------------------------
  Command              Description                   Example
  -------------------- ----------------------------- -----------------------------------
  `find`               Search files by               `find /etc -name "*.conf"`
                       name/size/etc.                

  `locate`             Search files from DB index.   `locate passwd`

  `updatedb`           Update locate DB.             `sudo updatedb`

  `grep`               Search by pattern.            `grep "error" logfile.log`

  `sort`               Sort file contents.           `sort names.txt`

  `cut`                Extract columns.              `cut -d: -f1 /etc/passwd`

  `tr`                 Translate characters.         `cat file | tr a-z A-Z`

  `awk`                Field/text processing.        `awk '{print $1}' file.txt`

  `sed`                Stream editor                 `sed 's/error/notice/g' file.txt`
                       (search/replace).             

  `wc`                 Count lines/words/bytes.      `wc -l file.txt`

  `column`             Format input into columns.    `cat data.txt | column -t`
  --------------------------------------------------------------------------------------

------------------------------------------------------------------------

## 💻 System Information

  Command   Description                     Example
  --------- ------------------------------- ---------------
  `lsblk`   Lists block devices.            `lsblk -f`
  `lsusb`   Lists USB devices.              `lsusb`
  `lspci`   Lists PCI devices.              `lspci -v`
  `lsof`    Lists open files & processes.   `lsof -i :22`

------------------------------------------------------------------------

## 🌐 Networking

  -------------------------------------------------------------------------------------------
  Command                    Description                   Example
  -------------------------- ----------------------------- ----------------------------------
  `ifconfig` *(deprecated)*  Configure/view interfaces.    `ifconfig eth0`

  `ip`                       Show/configure networking.    `ip addr`, `ip route`

  `netstat` *(deprecated)*   Show network connections.     `netstat -tulnp`

  `ss`                       Socket statistics (modern     `ss -tuln`
                             netstat).                     

  `curl`                     Transfer data from/to         `curl https://site.com`
                             servers.                      

  `wget`                     Download files.               `wget https://file.com/file.zip`

  `python3 -m http.server`   Start quick HTTP server.      `python3 -m http.server 8080`
  -------------------------------------------------------------------------------------------

------------------------------------------------------------------------

## ⚙️ Processes & Job Control

  Command        Description                 Example
  -------------- --------------------------- ------------------------
  `ps`           Snapshot of processes.      `ps aux`
  `jobs`         List background jobs.       `jobs`
  `bg`           Resume job in background.   `bg %1`
  `fg`           Bring job to foreground.    `fg %1`
  `kill`         Kill process by PID.        `kill -9 1234`
  `systemctl`    Manage services.            `systemctl status ssh`
  `journalctl`   View systemd logs.          `journalctl -u ssh`

------------------------------------------------------------------------

## 🧑‍🤝‍🧑 Users & Permissions

  Command      Description               Example
  ------------ ------------------------- -------------------------------
  `sudo`       Run as root/other user.   `sudo apt update`
  `su`         Switch user.              `su - user`
  `useradd`    Create new user.          `sudo useradd -m alice`
  `userdel`    Delete user.              `sudo userdel -r bob`
  `usermod`    Modify user.              `sudo usermod -aG sudo alice`
  `addgroup`   Add group.                `sudo addgroup devs`
  `delgroup`   Delete group.             `sudo delgroup devs`
  `passwd`     Change password.          `passwd user`
  `chmod`      Change permissions.       `chmod 755 script.sh`
  `chown`      Change owner/group.       `chown user:group file.txt`

------------------------------------------------------------------------

## 📦 Package Management

  --------------------------------------------------------------------------------------------
  Command              Description                   Example
  -------------------- ----------------------------- -----------------------------------------
  `dpkg`               Manage `.deb` packages.       `dpkg -i package.deb`

  `apt`                High-level package manager.   `apt install nmap`

  `aptitude`           Alternative package manager.  `aptitude search nginx`

  `snap`               Manage snap packages.         `snap install code --classic`

  `gem`                Ruby package manager.         `gem install rails`

  `pip`                Python package manager.       `pip install flask`

  `git`                Version control system.       `git clone https://github.com/repo.git`
  --------------------------------------------------------------------------------------------

------------------------------------------------------------------------

## 🛠 Practical Workflows

**1. Find large files in `/home`**

``` bash
find /home -type f -size +100M
```

**2. Monitor logs live**

``` bash
tail -f /var/log/syslog
```

**3. Kill a runaway process**

``` bash
ps aux | grep firefox
kill -9 <PID>
```

**4. Quick file transfer with Python**

``` bash
# On sender machine
python3 -m http.server 8080
# On receiver machine
wget http://<IP>:8080/file
```

**5. Check open ports**

``` bash
ss -tuln
```

------------------------------------------------------------------------
