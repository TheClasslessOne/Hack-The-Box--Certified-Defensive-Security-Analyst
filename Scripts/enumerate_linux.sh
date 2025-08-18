#!/usr/bin/env bash
# Complete but safe host/network/user/service/filesystem enumeration for Linux.
# USAGE: bash enumerate_linux.sh

set -uo pipefail
TS="$(date +%Y%m%d_%H%M%S)"
ROOT="$(pwd)/enum_linux_$TS"
mkdir -p "$ROOT"; OUT="$ROOT/summary.txt"; ERR="$ROOT/errors.txt"; JSON="$ROOT/facts.json"

log() { echo -e "$@" | tee -a "$OUT" >/dev/null; }
run() { local title="$1"; shift; log "=== $title ==="; "$@" 2>>"$ERR" | tee -a "$OUT" || true; echo >>"$OUT"; }
append_json() { printf '%s\n' "$1" >> "$JSON.tmp"; }

# ---- JSON scaffold ----
echo "{" > "$JSON.tmp"
append_json "\"run_timestamp\":\"$(date --iso-8601=seconds)\","
append_json "\"whoami\":\"$(whoami)\","
append_json "\"hostname\":\"$(hostname)\","
append_json "\"is_root\":$([ "$(id -u)" -eq 0 ] && echo true || echo false ),"

# ---- System / OS ----
log "=== System / OS ==="
if command -v lsb_release >/dev/null; then
  lsb_release -a 2>>"$ERR" | tee -a "$OUT"
fi
uname -a | tee -a "$OUT"
[ -f /etc/os-release ] && { cat /etc/os-release | tee -a "$OUT" >/dev/null; }
KVER="$(uname -r)"
append_json "\"kernel\":\"$KVER\","

# ---- CPU / Memory ----
run "CPU / Mem" sh -c 'lscpu || cat /proc/cpuinfo; echo; free -h || vm_stat || head -n 50 /proc/meminfo'

# ---- Environment ----
run "Environment & PATH" sh -c 'env | sort'

# ---- Network ----
run "IP / Ifaces" sh -c 'ip -brief addr || ifconfig -a'
run "Routes" sh -c 'ip route || route -n'
run "DNS" sh -c 'grep -E "^(nameserver|search)" /etc/resolv.conf || true'
run "ARP" sh -c 'ip neigh || arp -a'
run "Listening Ports (ss)" sh -c 'ss -tulpn || netstat -tulpn'

# JSON: IPs (properly quoted array, no jq dependency)
mapfile -t _IPS < <(ip -4 -o addr show 2>/dev/null | awk "{print \$4}" | cut -d/ -f1)
if [ "${#_IPS[@]}" -eq 0 ]; then
  append_json "\"ip_addresses\":[],"
else
  _jips=""
  for ip in "${_IPS[@]}"; do
    [ -n "$_jips" ] && _jips+=","
    _jips+="\"$ip\""
  done
  append_json "\"ip_addresses\":[${_jips}],"
fi

# ---- Users / Privs ----
run "whoami / id / lastlog" sh -c 'whoami; id; echo; (lastlog | head -n 50 || true)'
run "Logged-in sessions" sh -c 'who || w'
run "Sudoers (visible)" sh -c 'grep -r "^[^#].*ALL" /etc/sudoers /etc/sudoers.d 2>/dev/null || true'
run "Groups" sh -c 'groups || id -Gn'
run "Home dirs (perms)" sh -c 'ls -alh /home 2>/dev/null || true'

# ---- Packages / Services ----
run "Packages (dpkg/rpm)" sh -c '(dpkg -l 2>/dev/null || true) | head -n 120; (rpm -qa 2>/dev/null || true) | head -n 120'
run "Services (systemd)" sh -c 'systemctl list-unit-files --type=service --no-pager || true; echo; systemctl --type=service --state=running --no-pager || true'
run "Cron" sh -c 'for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null && echo "---"; done; ls -al /etc/cron* 2>/dev/null'
run "Timers (systemd)" sh -c 'systemctl list-timers --all --no-pager || true'

# ---- Security / Hardening ----
run "SELinux/AppArmor" sh -c 'getenforce 2>/dev/null || echo "SELinux: n/a"; aa-status 2>/dev/null || echo "AppArmor: n/a"'
run "Firewall" sh -c 'ufw status 2>/dev/null || firewall-cmd --list-all 2>/dev/null || iptables -S 2>/dev/null || nft list ruleset 2>/dev/null'
run "Kernel params" sh -c 'sysctl -a 2>/dev/null | egrep "^(net\.ipv4|kernel\.randomize_va_space|kernel\.yama|kernel\.unprivileged)" || true'

# ---- Filesystem / Permissions ----
run "Mounted filesystems" sh -c 'lsblk -f 2>/dev/null || true; echo; df -hT'
run "World-writable dirs (top)" sh -c 'find / -xdev -type d -perm -0002 -maxdepth 3 2>/dev/null | head -n 200'
run "SUID/SGID (common paths)" sh -c 'find /bin /sbin /usr/bin /usr/sbin -perm -4000 -o -perm -2000 2>/dev/null | sort'
run "Sticky/temp" sh -c 'ls -ld /tmp /var/tmp 2>/dev/null; find /tmp -maxdepth 1 -type f -printf "%TY-%Tm-%Td %TT %p\n" 2>/dev/null | sort | tail -n 100'

# ---- Interesting Configs ----
run "Hosts / Resolvers / Proxy" sh -c 'echo "-- /etc/hosts --"; cat /etc/hosts; echo; echo "-- Proxy env --"; env | egrep -i "http_proxy|https_proxy|no_proxy" || true'
run "SSH Config" sh -c 'sshd -T 2>/dev/null | sort || (cat /etc/ssh/sshd_config 2>/dev/null | egrep -v "^\s*#" || true)'
run "Known keys" sh -c 'for h in /home/*; do [ -d "$h/.ssh" ] && { echo "# $h/.ssh"; ls -al "$h/.ssh"; }; done; [ -d /root/.ssh ] && { echo "# /root/.ssh"; ls -al /root/.ssh; }'

# ---- Processes / Containers / Cloud ----
run "Top Processes" sh -c 'ps aux --sort=-%mem | head -n 35; echo; ps aux --sort=-%cpu | head -n 35'
run "Docker/Podman" sh -c 'docker ps -a 2>/dev/null || true; podman ps -a 2>/dev/null || true; grep -E "(docker|containerd)" /etc/group 2>/dev/null || true'
run "Kubernetes" sh -c 'kubectl get pods -A 2>/dev/null || true; crictl ps 2>/dev/null || true'
run "Cloud metadata (only prints endpoints)" sh -c 'echo "Potential metadata endpoints:"; printf "AWS: 169.254.169.254\nGCP: 169.254.169.254\nAzure: 169.254.169.254\n"'

# ---- Logs / Journal snapshot ----
run "Recent dmesg" sh -c 'dmesg | tail -n 200'
run "Journal (last boot, top 200)" sh -c 'journalctl -b -n 200 --no-pager 2>/dev/null || tail -n 200 /var/log/syslog 2>/dev/null || tail -n 200 /var/log/messages 2>/dev/null'

# ---- Exposures / Quick wins (read-only) ----
run "Readable interesting files" sh -c 'for f in /etc/passwd /etc/group /etc/shadow /etc/sudoers; do [ -r "$f" ] && ls -l "$f"; done; true'
run "World-readable SSH keys (listing only)" sh -c 'find / -xdev -type f -name "id_*" -perm -o+r 2>/dev/null | head -n 50'

# ---- Package updates available (no changes) ----
run "Available updates (no changes)" sh -c 'if command -v apt >/dev/null; then apt -s upgrade 2>/dev/null | egrep "upgraded,|NEW packages" || true; elif command -v dnf >/dev/null; then dnf check-update 2>/dev/null | head -n 50; elif command -v yum >/dev/null; then yum check-update 2>/dev/null | head -n 50; fi'

# ---- JSON finalize ----
# listeners: prefer JSON via jq if present; else, empty array
if command -v jq >/dev/null 2>&1; then
  append_json "\"listeners\":$(ss -tulpn 2>/dev/null | awk 'NR>1{print}' | jq -R -s -c 'split("\n")[:-1]')"
else
  append_json "\"listeners\":[]"
fi
echo "}" >> "$JSON.tmp"
mv "$JSON.tmp" "$JSON"

echo "Done. Results in: $ROOT"
