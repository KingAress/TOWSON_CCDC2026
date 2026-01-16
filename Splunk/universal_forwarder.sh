#!/bin/bash
# ============================================================
# Splunk Universal Forwarder (UF) Install + Configure Script
# Works on:
#   - RHEL-family via RPM
#   - Debian/Ubuntu via TGZ
#
# What it does:
#  1) Detect install method (rpm vs tgz)
#  2) Download Splunk UF
#  3) Install UF to /opt/splunkforwarder
#  4) Seed first admin user/pass (no interactive prompt)
#  5) Configure outputs.conf to forward to INDEXER:9997
#  6) Configure inputs.conf (monitors common log files)
#  7) Enable boot-start + start UF
# ============================================================

set -euo pipefail

# ----------------------------
# Variables you SHOULD edit
# ----------------------------
SPLUNK_INDEXER_HOST="192.168.254.241"
SPLUNK_INDEXER_PORT="9997"

UF_ADMIN_USER="admin"
UF_ADMIN_PASS="password1!"              # Change this

SPLUNK_USER="splunk"
SPLUNK_HOME="/opt/splunkforwarder"
DOWNLOAD_DIR="/tmp/splunk_uf_install"

# ----------------------------
# UF version + URLs
# ----------------------------
UF_VER="10.0.2"

# UF 10.0.2 URLs (EDIT THESE to match your exact Splunk build/arch)
UF_TGZ_URL="https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-REPLACE_ME-linux-2.6-x86_64.tgz"
UF_RPM_URL="https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-REPLACE_ME.x86_64.rpm"

# Monitors to add (script will only monitor files/dirs that exist)
MONITOR_PATHS=(
  "/var/log/syslog"
  "/var/log/messages"
  "/var/log/auth.log"
  "/var/log/secure"
  "/var/log/audit/audit.log"
  "/var/log/nginx"
  "/var/log/httpd"
  "/var/log/apache2"
)

# ----------------------------
# Helpers
# ----------------------------
log()  { echo -e "[+] $*"; }
warn() { echo -e "[!] $*"; }
die()  { echo -e "[X] $*" >&2; exit 1; }

need_root() {
  if [[ ${EUID} -ne 0 ]]; then
    die "Must be run as root (use sudo)."
  fi
}

# Detect install method:
# - Prefer RPM if rpm tooling exists (RHEL-family)
# - Otherwise use TGZ (Debian/Ubuntu or minimal distros)
detect_install_method() {
  if command -v rpm >/dev/null 2>&1; then
    echo "rpm"
  else
    echo "tgz"
  fi
}

ensure_tools() {
  # Need wget or curl; and tar for tgz
  local method="$1"

  if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
    warn "Neither wget nor curl found; installing downloader..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y wget || apt-get install -y curl
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y wget || dnf install -y curl
    elif command -v yum >/dev/null 2>&1; then
      yum install -y wget || yum install -y curl
    else
      die "Could not install wget/curl (no supported package manager found)."
    fi
  fi

  if [[ "$method" == "tgz" ]]; then
    if ! command -v tar >/dev/null 2>&1; then
      warn "tar not found; installing tar..."
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y tar
      elif command -v dnf >/dev/null 2>&1; then
        dnf install -y tar
      elif command -v yum >/dev/null 2>&1; then
        yum install -y tar
      else
        die "Could not install tar (no supported package manager found)."
      fi
    fi
  fi
}

download_file() {
  local url="$1"
  local out="$2"

  mkdir -p "$(dirname "$out")"

  if command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    curl -fsSL "$url" -o "$out"
  fi
}

uf_installed() {
  [[ -x "$SPLUNK_HOME/bin/splunk" ]]
}

ensure_splunk_user() {
  if id "$SPLUNK_USER" >/dev/null 2>&1; then
    log "OS user '$SPLUNK_USER' exists."
  else
    log "Creating OS user '$SPLUNK_USER'..."
    useradd --system --create-home --shell /bin/bash "$SPLUNK_USER" || true
  fi
}

seed_first_admin_if_needed() {
  local passwd_file="$SPLUNK_HOME/etc/passwd"
  local local_dir="$SPLUNK_HOME/etc/system/local"
  local seed_file="$local_dir/user-seed.conf"

  if [[ -f "$passwd_file" ]]; then
    log "Forwarder already initialized ($passwd_file exists). Not seeding admin."
    return 0
  fi

  log "Seeding initial UF admin credentials (no interactive prompt)..."
  mkdir -p "$local_dir"
  cat > "$seed_file" <<EOF
[user_info]
USERNAME = ${UF_ADMIN_USER}
PASSWORD = ${UF_ADMIN_PASS}
EOF

  chown "$SPLUNK_USER:$SPLUNK_USER" "$seed_file" || true
  chmod 600 "$seed_file" || true
}

start_uf_first_time() {
  log "Starting Splunk UF (accept license, no prompt)..."
  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME" || true

  sudo -u "$SPLUNK_USER" "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt >/dev/null 2>&1 || true

  if "$SPLUNK_HOME/bin/splunk" status >/dev/null 2>&1; then
    log "UF is running."
  else
    warn "UF may not be running yet. Check: $SPLUNK_HOME/var/log/splunk/splunkd.log"
  fi
}

configure_outputs() {
  local local_dir="$SPLUNK_HOME/etc/system/local"
  local outputs="$local_dir/outputs.conf"

  log "Configuring outputs.conf to forward to ${SPLUNK_INDEXER_HOST}:${SPLUNK_INDEXER_PORT}..."
  mkdir -p "$local_dir"

  cat > "$outputs" <<EOF
[tcpout]
defaultGroup = primary_indexers

[tcpout:primary_indexers]
server = ${SPLUNK_INDEXER_HOST}:${SPLUNK_INDEXER_PORT}
EOF

  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$local_dir" || true
}

configure_inputs() {
  local local_dir="$SPLUNK_HOME/etc/system/local"
  local inputs="$local_dir/inputs.conf"

  log "Writing inputs.conf (monitor common logs if present)..."
  mkdir -p "$local_dir"

  cat > "$inputs" <<'EOF'
# Autogenerated by UF install script
# Only monitors paths that exist on this host.
EOF

  for p in "${MONITOR_PATHS[@]}"; do
    if [[ -f "$p" ]]; then
      cat >> "$inputs" <<EOF

[monitor://${p}]
disabled = false
index = main
EOF
    elif [[ -d "$p" ]]; then
      cat >> "$inputs" <<EOF

[monitor://${p}]
disabled = false
index = main
whitelist = \.log$
EOF
    fi
  done

  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$local_dir" || true
}

enable_boot_start() {
  log "Enabling UF boot-start (systemd-managed)..."
  "$SPLUNK_HOME/bin/splunk" enable boot-start -user "$SPLUNK_USER" --systemd-managed >/dev/null 2>&1 || true

  systemctl daemon-reload || true
  systemctl enable SplunkForwarder 2>/dev/null || systemctl enable splunkforwarder 2>/dev/null || true
}

restart_uf() {
  log "Restarting UF to apply config..."
  sudo -u "$SPLUNK_USER" "$SPLUNK_HOME/bin/splunk" restart >/dev/null 2>&1 || true
}

show_status() {
  echo
  log "UF binary: $SPLUNK_HOME/bin/splunk"
  log "Indexer target: ${SPLUNK_INDEXER_HOST}:${SPLUNK_INDEXER_PORT}"
  echo

  log "UF status:"
  "$SPLUNK_HOME/bin/splunk" status || true

  echo
  log "Configured forward-server(s) (from outputs.conf):"
  grep -R "server" "$SPLUNK_HOME/etc/system/local/outputs.conf" || true

  echo
  log "Listening sockets (UF management / internal):"
  ss -lntp | grep splunk || true

  echo
  log "Tip: to watch UF connection behavior:"
  echo "     tail -f $SPLUNK_HOME/var/log/splunk/splunkd.log | egrep 'TcpOutputProc|Connected|connect|WARN|ERROR'"
}

# ----------------------------
# Install UF
# ----------------------------
install_uf_rpm() {
  mkdir -p "$DOWNLOAD_DIR"
  local rpm_file="$DOWNLOAD_DIR/splunkforwarder-${UF_VER}.rpm"

  log "Downloading UF (rpm)..."
  download_file "$UF_RPM_URL" "$rpm_file"

  log "Installing UF RPM..."
  # Prefer package manager if available
  if command -v dnf >/dev/null 2>&1; then
    dnf -y install "$rpm_file"
  elif command -v yum >/dev/null 2>&1; then
    yum -y install "$rpm_file"
  else
    rpm -i "$rpm_file"
  fi
}

install_uf_tgz() {
  mkdir -p "$DOWNLOAD_DIR"
  local tgz_file="$DOWNLOAD_DIR/splunkforwarder-${UF_VER}.tgz"

  log "Downloading UF (tgz)..."
  download_file "$UF_TGZ_URL" "$tgz_file"

  # If UF already exists, back it up instead of clobbering
  if [[ -d "$SPLUNK_HOME" ]]; then
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    warn "Existing $SPLUNK_HOME found. Moving to ${SPLUNK_HOME}.bak.${ts}"
    # Try to stop cleanly if it's a valid UF
    if [[ -x "$SPLUNK_HOME/bin/splunk" ]]; then
      "$SPLUNK_HOME/bin/splunk" stop >/dev/null 2>&1 || true
    fi
    mv "$SPLUNK_HOME" "${SPLUNK_HOME}.bak.${ts}"
  fi

  log "Extracting TGZ to /opt..."
  tar -xzf "$tgz_file" -C /opt

  if ! uf_installed; then
    die "TGZ install finished but $SPLUNK_HOME/bin/splunk not found."
  fi
}

install_uf() {
  local method="$1"

  if uf_installed; then
    log "UF already installed at $SPLUNK_HOME"
    return 0
  fi

  ensure_tools "$method"

  if [[ "$method" == "rpm" ]]; then
    install_uf_rpm
  else
    install_uf_tgz
  fi

  if ! uf_installed; then
    die "UF install finished but $SPLUNK_HOME/bin/splunk not found."
  fi

  log "UF installed successfully."
}

# ----------------------------
# Main
# ----------------------------
need_root

INSTALL_METHOD="$(detect_install_method)"
log "Detected install method: $INSTALL_METHOD"

install_uf "$INSTALL_METHOD"
ensure_splunk_user
seed_first_admin_if_needed
start_uf_first_time
configure_outputs
configure_inputs
enable_boot_start
restart_uf
show_status

log "Done. UF should now forward logs to ${SPLUNK_INDEXER_HOST}:${SPLUNK_INDEXER_PORT}"
