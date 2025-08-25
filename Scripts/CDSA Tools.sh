#!/usr/bin/env bash
set -euo pipefail

DEST="${1:-$HOME/cdsa-tools}"
mkdir -p "$DEST"
cd "$DEST"

# Ensure git + curl exist
if ! command -v git >/dev/null 2>&1; then
  echo "[!] git not found. Install git and re-run." >&2
  exit 1
fi

clone() {
  local name="$1" url="$2"
  if [ -d "$name" ]; then
    echo "[=] $name already exists, pulling latest..."
    git -C "$name" pull --ff-only || true
  else
    echo "[+] Cloning $name ..."
    git clone --depth 1 "$url" "$name" || echo "[!] Failed to clone $name"
  fi
}

# --- Endpoint & Artifact Analysis
clone "KapeFiles"              "https://github.com/EricZimmerman/KapeFiles.git"
clone "RegRipper3.0"           "https://github.com/keydet89/RegRipper3.0.git"
clone "chainsaw"               "https://github.com/WithSecureLabs/chainsaw.git"
clone "sigma"                  "https://github.com/SigmaHQ/sigma.git"

# --- Network Forensics
clone "zeek"                   "https://github.com/zeek/zeek.git"
clone "tcpdump"                "https://github.com/the-tcpdump-group/tcpdump.git"

# --- Log Analysis & Threat Hunting
clone "timesketch"             "https://github.com/google/timesketch.git"
clone "elastic-detection-rules""https://github.com/elastic/detection-rules.git"
clone "hayabusa"               "https://github.com/Yamato-Security/hayabusa.git"
clone "jq"                     "https://github.com/jqlang/jq.git"

# --- Linux IR
clone "Loki"                   "https://github.com/Neo23x0/Loki.git"
clone "osquery"                "https://github.com/osquery/osquery.git"
clone "p0f"                    "https://github.com/p0f/p0f.git"

# --- Passwords, Hashes & Memory
clone "volatility3"            "https://github.com/volatilityfoundation/volatility3.git"
clone "impacket"               "https://github.com/fortra/impacket.git"
clone "hashcat"                "https://github.com/hashcat/hashcat.git"
clone "john"                   "https://github.com/openwall/john.git"

# --- Detection Eng & Playbooks
clone "attack-navigator"       "https://github.com/mitre-attack/attack-navigator.git"
clone "atomic-red-team"        "https://github.com/redcanaryco/atomic-red-team.git"
clone "sysmon-config"          "https://github.com/SwiftOnSecurity/sysmon-config.git"

echo
echo "[✔] Done. Repos in: $DEST"
echo "[i] Many projects have build steps. Common examples:"
echo "    - chainsaw: cargo build --release"
echo "    - hayabusa: download release or build with dotnet"
echo "    - volatility3: python3 -m venv venv && pip install -r requirements.txt"
echo "    - impacket: pip install ."
echo "    - jq: build with autotools (README in repo)"
