#!/bin/bash

# ============================================================
# iptables Skeleton Script
# Purpose: Establish a secure baseline firewall using iptables
# Scope: Debian / RHEL-family systems
# ============================================================

set -euo pipefail

# ---------- Check if running as root ----------
if [[ ${EUID:-0} -ne 0 ]]; then
    echo "[!] This script must be run as root."
    exit 1
fi

# ---------- Verify iptables ----------
echo "[*] Checking for iptables..."
if ! command -v iptables >/dev/null 2>&1; then
    echo "[!] iptables not found. Install it before running this script."
    exit 1
fi
echo "[+] iptables is available."

# ---------- Flush Existing Rules ----------
echo "[*] Flushing existing rules..."

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# ---------- Default Policies ----------
echo "[*] Setting default policies..."

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# ---------- Baseline Rules ----------
echo "[*] Applying baseline rules..."

iptables -A INPUT -i lo -j ACCEPT # Allow loopback traffic

# ---------- Rule Section ----------
echo "[*] Setting rules..."

iptables -A INPUT -p tcp --dport 2222 -m conntrack --ctstate NEW -j ACCEPT # Hardened SSH for recovery
iptables -A INPUT -p tcp --dport 8000 -m conntrack --ctstate NEW -j ACCEPT # Splunk UI
iptables -A INPUT -p tcp --dport 9997 -m conntrack --ctstate NEW -j ACCEPT # Splunk Universal Forwarder



# SSH rate limiting
iptables -A INPUT -p tcp --dport 2222 -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 2222 -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

echo "[*] Service rules applied."

# ---------- Optional Logging ----------
echo "[*] Adding rate-limited logging for dropped packets..."

iptables -A INPUT -m limit --limit 5/min -j LOG \
  --log-prefix "IPTABLES-DROP: " --log-level 4
 
# ---------- Persistence (Skeleton Only) ----------
echo "[*] Persistence not enforced by this script."
echo "    Debian: use iptables-persistent or netfilter-persistent"
echo "    RHEL:   use iptables-services (service iptables save)"

# ---------- Final Status ----------
echo "[*] Final iptables rule set:"
iptables -L -n -v --line-numbers

echo "[+] Iptables script completed successfully."

scp -T -J ccdc@10.23.65.6:10033 ./copy.txt zathras@192.168.255.17:/home/zathras/Desktop/copy.txt