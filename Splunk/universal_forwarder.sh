#!/bin/bash
# ============================================================
# Splunk Universal Forwarder (UF) Install + Configure Script
# Works on: Debian/Ubuntu (deb), RHEL-family (rpm)
#
# What it does:
#  1) Detect OS package type (deb/rpm)
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
SPLUNK_INDEXER_HOST="192.168.254.241"   # <-- your Splunk server LAN IP
SPLUNK_INDEXER_PORT="9997"

UF_ADMIN_USER="admin"                   # Forwarder local admin (for CLI auth if needed)
UF_ADMIN_PASS="password1!"              # Change this

SPLUNK_USER="splunk"                    # OS account to run UF
SPLUNK_HOME="/opt/splunkforwarder"
DOWNLOAD_DIR="/tmp/splunk_uf_install"

# Pick UF version + URLs (match what you used)
UF_VER="9.1.1"
# These are the same builds you referenced earlier:
UF_DEB_URL="https://download.splunk.com/products/universalforwarder/releases/9.1.1/linux/splunkforwarder-9.1.1-64e843ea36b1-linux-2.6-amd64.deb"
UF_RPM_URL="https://download.splunk.com/products/universalforwarder/releases/9.1.1/linux/splunkforwarder-9.1.1-64e843ea36b1.x86_64.rpm"

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

detect_pkg_type() {
  if command -v dpkg >/dev/null 2>&1; then
    echo "deb"
  elif command -v rpm >/dev/null 2>&1; then
    echo "rpm"
  else
    die "Neither dpkg nor rpm found. Unsupported system."
  fi
}

ensure_tools() {
  # We need wget or curl
  if command -v wget >/dev/null 2>&1; then
    return 0
  fi
  if command -v curl >/dev/null 2>&1; then
    return 0
  fi

  local pkgtype="$1"
  warn "Neither wget nor curl found; installing downloader..."
  if [[ "$pkgtype" == "deb" ]]; then
    apt-get update -y
    apt-get install -y wget || apt-get install -y curl
  else
    (command -v dnf >/dev/null 2>&1 && dnf install -y wget) || \
    (command -v yum >/dev/null 2>&1 && yum install -y wget) || \
    die "Could not install wget via yum/dnf."
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
  # Splunk UF will prompt for admin creation at first start unless seeded.
  # We only seed if no passwd file exists yet (first init).
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
  # Start UF non-interactively
  log "Starting Splunk UF (accept license, no prompt)..."
  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$SPLUNK_HOME" || true

  # --answer-yes + --no-prompt prevents hanging on prompts
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

# Optional: keep some buffering if the indexer is temporarily unreachable
# (adjust to taste for competition environments)
#[tcpout-server://${SPLUNK_INDEXER_HOST}:${SPLUNK_INDEXER_PORT}]
EOF

  chown -R "$SPLUNK_USER:$SPLUNK_USER" "$local_dir" || true
}

configure_inputs() {
  local local_dir="$SPLUNK_HOME/etc/system/local"
  local inputs="$local_dir/inputs.conf"

  log "Writing inputs.conf (monitor common logs if present)..."
  mkdir -p "$local_dir"

  # Start a fresh inputs.conf so your runs are repeatable
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
  # This sets up systemd unit management for Splunk UF
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

install_uf() {
  local pkgtype="$1"
  mkdir -p "$DOWNLOAD_DIR"
  cd "$DOWNLOAD_DIR"

  if uf_installed; then
    log "UF already installed at $SPLUNK_HOME"
    return 0
  fi

  ensure_tools "$pkgtype"

  if [[ "$pkgtype" == "deb" ]]; then
    local deb_file="$DOWNLOAD_DIR/splunkforwarder-${UF_VER}.deb"
    log "Downloading UF (deb)..."
    download_file "$UF_DEB_URL" "$deb_file"
    log "Installing UF package..."
    dpkg -i "$deb_file" || (apt-get update -y && apt-get -f install -y)
  else
    local rpm_file="$DOWNLOAD_DIR/splunkforwarder-${UF_VER}.rpm"
    log "Downloading UF (rpm)..."
    download_file "$UF_RPM_URL" "$rpm_file"
    log "Installing UF package..."
    rpm -i "$rpm_file"
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

PKG_TYPE="$(detect_pkg_type)"
log "Detected package type: $PKG_TYPE"

install_uf "$PKG_TYPE"
ensure_splunk_user
seed_first_admin_if_needed
start_uf_first_time
configure_outputs
configure_inputs
enable_boot_start
restart_uf
show_status

log "Done. UF should now forward logs to ${SPLUNK_INDEXER_HOST}:${SPLUNK_INDEXER_PORT}"
