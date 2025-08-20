# 📘 Linux Command Reference (Enhanced & Organized)

  -------------------------------------------------------------------------------------------------------------
  **Category**        **Command**                **Description**      **Common Usage / Examples**
  ------------------- -------------------------- -------------------- -----------------------------------------
  **Help &            `man <tool>`               Opens the manual     `man ls` → view documentation for `ls`.
  Documentation**                                page for a           
                                                 command/tool.        

                      `<tool> -h` or `--help`    Prints a help page   `ls --help`
                                                 (flags/usage).       

                      `apropos <keyword>`        Searches man page    `apropos network`
                                                 descriptions for a   
                                                 keyword.             

  **User Information  `whoami`                   Displays the current `whoami`
  & System Identity**                            username.            

                      `id`                       Shows user ID (UID), `id username`
                                                 group ID (GID), and  
                                                 group memberships.   

                      `hostname`                 Prints or sets the   `hostnamectl set-hostname newname`
                                                 system's hostname.   

                      `uname`                    Displays             `uname -a` → show all details.
                                                 system/kernel info.  

                      `who`                      Lists currently      `who`
                                                 logged-in users.     

                      `env`                      Prints environment   `env | grep PATH`
                                                 variables or runs a  
                                                 command in a         
                                                 modified             
                                                 environment.         

  **File & Directory  `pwd`                      Prints current       `pwd`
  Management**                                   working directory.   

                      `ls`                       Lists directory      `ls -l` (long format), `ls -a` (show
                                                 contents.            hidden).

                      `cd`                       Change directory.    `cd /etc`

                      `tree`                     Recursive directory  `tree /var/log`
                                                 listing.             

                      `touch`                    Creates an empty     `touch file.txt`
                                                 file or updates      
                                                 timestamp.           

                      `mkdir`                    Creates a directory. `mkdir -p /tmp/test/dir`

                      `cp`                       Copies               `cp file1 file2`, `cp -r dir1 dir2`
                                                 files/directories.   

                      `mv`                       Moves/renames files  `mv old.txt new.txt`
                                                 or directories.      

                      `rm`                       Removes files or     `rm file.txt`, `rm -rf dir/`
                                                 directories.         

  **Text Viewing &    `cat`                      Concatenate and      `cat file.txt`
  Editing**                                      display file         
                                                 contents.            

                      `more`                     Basic pager for      `cat file.txt | more`
                                                 viewing text.        

                      `less`                     Enhanced pager with  `less /var/log/syslog`
                                                 search/navigation.   

                      `head`                     Shows first 10 lines `head -20 file.txt`
                                                 of file.             

                      `tail`                     Shows last 10 lines  `tail -f logfile.log` (live updates).
                                                 of file.             

                      `nano`                     Terminal text        `nano script.sh`
                                                 editor.              

  **Search &          `find`                     Search files by      `find /etc -name "*.conf"`
  Processing**                                   name, size, time,    
                                                 etc.                 

                      `locate`                   Search files using a `locate passwd`
                                                 prebuilt index.      

                      `updatedb`                 Updates the locate   `sudo updatedb`
                                                 index.               

                      `grep`                     Search text by       `grep "error" logfile.log`
                                                 pattern.             

                      `sort`                     Sorts lines in text. `sort file.txt`

                      `cut`                      Extracts specific    `cut -d: -f1 /etc/passwd`
                                                 columns or           
                                                 characters.          

                      `tr`                       Translate/replace    `cat file | tr a-z A-Z`
                                                 characters.          

                      `awk`                      Text processing      `awk '{print $1}' file.txt`
                                                 language.            

                      `sed`                      Stream editor for    `sed 's/error/notice/g' file.txt`
                                                 text                 
                                                 transformations.     

                      `wc`                       Count lines, words,  `wc -l file.txt`
                                                 and characters.      

                      `column`                   Format text into     `cat file | column -t`
                                                 neat columns.        

  **System            `lsblk`                    Lists block storage  `lsblk -f`
  Information**                                  devices.             

                      `lsusb`                    Lists USB devices.   `lsusb`

                      `lspci`                    Lists PCI devices.   `lspci -v`

                      `lsof`                     Lists open files and `lsof -i :80`
                                                 the processes using  
                                                 them.                

  **Networking**      `ifconfig` *(deprecated)*  Configure/view       `ifconfig eth0`
                                                 network interfaces.  

                      `ip`                       Modern tool to       `ip addr`, `ip route`
                                                 show/configure       
                                                 networking.          

                      `netstat` *(deprecated)*   Show network         `netstat -tulnp`
                                                 connections and      
                                                 stats.               

                      `ss`                       Modern replacement   `ss -tuln`
                                                 for netstat.         

                      `curl`                     Transfer data        `curl https://example.com`
                                                 from/to servers.     

                      `wget`                     Download files via   `wget https://file.com/file.zip`
                                                 HTTP/FTP.            

                      `python3 -m http.server`   Start a quick web    `python3 -m http.server 8080`
                                                 server (default port 
                                                 8000).               

  **Processes & Job   `ps`                       Snapshot of          `ps aux`
  Control**                                      processes.           

                      `jobs`                     List background      `jobs`
                                                 jobs.                

                      `bg`                       Resume a process in  `bg %1`
                                                 background.          

                      `fg`                       Bring a process to   `fg %1`
                                                 foreground.          

                      `kill`                     Send signal to       `kill -9 <PID>`
                                                 process (default:    
                                                 TERM).               

                      `systemctl`                Manage systemd       `systemctl status ssh`
                                                 services.            

                      `journalctl`               View systemd logs.   `journalctl -u ssh`

  **Users &           `sudo`                     Run command as       `sudo apt update`
  Permissions**                                  another user         
                                                 (default: root).     

                      `su`                       Switch user          `su - username`
                                                 (default: root).     

                      `useradd`                  Create a new user.   `sudo useradd -m newuser`

                      `userdel`                  Delete a user.       `sudo userdel -r olduser`

                      `usermod`                  Modify a user        `usermod -aG sudo user`
                                                 account.             

                      `addgroup`                 Add a new group.     `sudo addgroup devs`

                      `delgroup`                 Remove a group.      `sudo delgroup devs`

                      `passwd`                   Change user          `passwd username`
                                                 password.            

                      `chmod`                    Change file          `chmod 755 script.sh`
                                                 permissions.         

                      `chown`                    Change file          `chown user:group file.txt`
                                                 owner/group.         

  **Package           `dpkg`                     Install/manage       `dpkg -i package.deb`
  Management**                                   Debian packages.     

                      `apt`                      Debian/Ubuntu        `apt install nmap`
                                                 package manager.     

                      `aptitude`                 Alternative to apt   `aptitude search nginx`
                                                 with UI.             

                      `snap`                     Manage snap          `snap install code --classic`
                                                 packages.            

                      `gem`                      Ruby package         `gem install rails`
                                                 manager.             

                      `pip`                      Python package       `pip install requests`
                                                 manager.             

                      `git`                      Version control      `git clone https://github.com/repo.git`
                                                 system.              

  **Miscellaneous**   `clear`                    Clears terminal      `clear`
                                                 screen.              

                      `which`                    Shows full path of a `which python3`
                                                 command.             
  -------------------------------------------------------------------------------------------------------------
