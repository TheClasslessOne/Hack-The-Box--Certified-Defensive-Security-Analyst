#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target> [--full]"
  exit 1
fi

TARGET="$1"
FULL=${2:-}

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="recon_${TARGET}_${STAMP}"
mkdir -p "$OUT"/{basic,dns,ports,services,web,ssl,smb,snmp,notes}

log(){ printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
have(){ command -v "$1" &>/dev/null; }

# ---------- Basic host info ----------
basic(){
  log "Basic host checks -> $OUT/basic"
  {
    echo "Target: $TARGET"
    echo "Local date: $(date)"
    echo "Local user: $(id 2>/dev/null || true)"
    echo
    echo "== /etc/hosts (first 10) =="
    head -n 10 /etc/hosts 2>/dev/null || true
  } > "$OUT/basic/context.txt"

  if have ping; then
    ping -c 1 -W 1 "$TARGET" > "$OUT/basic/ping.txt" 2>&1 || true
  fi

  if have traceroute; then
    traceroute -n -w 2 -q 1 "$TARGET" > "$OUT/basic/traceroute.txt" 2>&1 || true
  elif have tracepath; then
    tracepath -n "$TARGET" > "$OUT/basic/traceroute.txt" 2>&1 || true
  fi

  if have whois; then
    (whois "$TARGET" || true) > "$OUT/basic/whois.txt" 2>&1 || true
  fi
}

# ---------- DNS ----------
dns(){
  log "DNS enumeration -> $OUT/dns"
  if have dig; then
    {
      echo ";; dig A/AAAA/CNAME"
      dig +short A "$TARGET"
      dig +short AAAA "$TARGET"
      dig +short CNAME "$TARGET"
      echo
      echo ";; NS / MX"
      dig +short NS "$TARGET"
      dig +short MX "$TARGET"
      echo
      echo ";; Zone transfer attempt (AXFR) against NS (may fail)"
      for ns in $(dig +short NS "$TARGET"); do
        dig @"$ns" "$TARGET" AXFR +time=3 +tries=1
      done
    } > "$OUT/dns/dig.txt" 2>&1 || true
  elif have nslookup; then
    nslookup "$TARGET" > "$OUT/dns/nslookup.txt" 2>&1 || true
  fi
}

# ---------- Port scanning (nmap preferred) ----------
scan_ports(){
  log "Port scanning -> $OUT/ports"
  if have nmap; then
    # Quick TCP scan
    nmap -Pn -T4 --top-ports 1000 -sS -sV "$TARGET" -oA "$OUT/ports/tcp_top" || true
    # Light UDP
    nmap -Pn -T4 --top-ports 50 -sU "$TARGET" -oA "$OUT/ports/udp_top" || true

    if [[ "$FULL" == "--full" ]]; then
      nmap -Pn -T4 -p- -sS -sV -sC "$TARGET" -oA "$OUT/ports/tcp_full" || true
      nmap -Pn -T4 --top-ports 200 -sU "$TARGET" -oA "$OUT/ports/udp_more" || true
    fi
  else
    # Fallback with nc if nmap missing (basic TCP 1-1024)
    if have nc; then
      for p in $(seq 1 1024); do
        (echo >/dev/tcp/"$TARGET"/"$p") >/dev/null 2>&1 && echo "open $p/tcp"
      done > "$OUT/ports/nc_tcp_1_1024.txt"
    fi
  fi
}

# ---------- Banner grabbing common services ----------
banners(){
  log "Banner grabbing -> $OUT/services"
  g(){ # generic grab
    local port="$1" name="$2"
    if have timeout; then
      timeout 3 bash -c "exec 3<>/dev/tcp/$TARGET/$port; echo -e 'HEAD / HTTP/1.0\r\n\r\n' >&3; cat <&3 | head -n 10" \
        > "$OUT/services/${name}_${port}.txt" 2>/dev/null || true
    fi
  }
  # Try common ports quickly
  g 22 ssh
  g 23 telnet
  g 25 smtp
  g 80 http
  g 110 pop3
  g 139 netbios
  g 143 imap
  g 389 ldap
  g 445 smb
  g 631 cups
  g 3306 mysql
  g 3389 rdp
  g 5900 vnc
}

# ---------- HTTP/HTTPS checks ----------
web_enum(){
  log "Web checks -> $OUT/web"
  for port in 80 8080 8000 8888; do
    if have curl; then
      curl -ksI "http://$TARGET:$port/" > "$OUT/web/http_${port}_headers.txt" 2>&1 || true
      curl -ks "http://$TARGET:$port/" | head -n 200 > "$OUT/web/http_${port}_body_head.txt" 2>&1 || true
    fi
  done
  for port in 443 8443 9443; do
    if have curl; then
      curl -ksI "https://$TARGET:$port/" > "$OUT/web/https_${port}_headers.txt" 2>&1 || true
      curl -ks "https://$TARGET:$port/" | head -n 200 > "$OUT/web/https_${port}_body_head.txt" 2>&1 || true
    fi
  done
}

# ---------- TLS details ----------
ssl_enum(){
  log "TLS details -> $OUT/ssl"
  if have openssl; then
    for port in 443 8443 993 995 587 465; do
      (echo | openssl s_client -connect "$TARGET:$port" -servername "$TARGET" -brief 2>/dev/null \
        | sed 's/\r//g') > "$OUT/ssl/${port}.txt" || true
    done
  fi
}

# ---------- SMB quick checks ----------
smb_enum(){
  if have smbclient; then
    log "SMB enumeration -> $OUT/smb"
    smbclient -L "//$TARGET" -N > "$OUT/smb/shares.txt" 2>&1 || true
  fi
}

# ---------- SNMP quick checks ----------
snmp_enum(){
  if have snmpwalk; then
    log "SNMP walk (community 'public') -> $OUT/snmp"
    snmpwalk -v1 -c public -t 2 -r 1 "$TARGET" 1.3.6.1 > "$OUT/snmp/walk_public.txt" 2>&1 || true
  fi
}

# ---------- CUPS specific (common in HTB printer boxes) ----------
cups_enum(){
  if have curl; then
    log "CUPS quick check -> $OUT/services/cups_631.txt"
    curl -s "http://$TARGET:631/admin/log/error_log?&" | tail -n 200 > "$OUT/services/cups_631.txt" 2>&1 || true
  fi
}

# ---------- Run all ----------
basic
dns
scan_ports
banners
web_enum
ssl_enum
smb_enum
snmp_enum
cups_enum

log "Done. Results saved under: $OUT"
echo "Tip: open a second terminal and run: tree $OUT  (or ls -R $OUT) to review."
