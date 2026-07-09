#!/usr/bin/env bash
# vpn-ui test unit — host backend bootstrap.
#
# Installs + initialises everything the harness needs ON THE HOST:
#   * incus         — the VM backend that launches the distro matrix
#   * python3 + pip — drives the harness
#   * python deps   — requests (requirements.txt); TOML config uses stdlib tomllib
#   * incus init    — a minimal storage pool + default profile
#
# Cross-distro package managers: apt (Debian/Ubuntu) · dnf (Fedora) ·
# yum (RHEL/Alma/Rocky) · pacman (Arch). Idempotent: only installs what is
# missing, safe to re-run. run.sh calls this automatically when the backend
# isn't ready; run it by hand with `sudo ./setup.sh`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { echo "[setup] $*"; }
warn() { echo "[setup] WARN: $*" >&2; }
die()  { echo "[setup] FATAL: $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "must run as root (installs packages, starts incus)."

# --------------------------------------------------------------- os / pkg mgr
os_field() { ( . /etc/os-release 2>/dev/null && eval "echo \${$1:-}" ); }

PM=""
detect_pm() {
  for c in apt-get dnf yum pacman; do
    if command -v "$c" >/dev/null 2>&1; then PM="$c"; return; fi
  done
  die "no supported package manager found (need apt/dnf/yum/pacman)."
}

pm_refresh() {
  case "$PM" in
    apt-get) apt-get update -y ;;
    pacman)  pacman -Sy --noconfirm ;;
    dnf|yum) : ;;   # dnf/yum refresh metadata on demand
  esac
}

pm_install() {  # pm_install pkg [pkg...]
  [[ $# -gt 0 ]] || return 0
  log "installing: $*"
  case "$PM" in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    dnf)     dnf install -y "$@" ;;
    yum)     yum install -y "$@" ;;
    pacman)  pacman -S --needed --noconfirm "$@" ;;
  esac
}

# ------------------------------------------------------------------- python
ensure_python() {
  if command -v python3 >/dev/null 2>&1 \
     && python3 -m pip --version >/dev/null 2>&1; then
    return
  fi
  log "installing python3 + pip"
  case "$PM" in
    pacman) pm_install python python-pip ;;
    *)      pm_install python3 python3-pip ;;
  esac
  command -v python3 >/dev/null 2>&1 || die "python3 install failed."
}

ensure_py_deps() {
  # TOML config is parsed with the stdlib tomllib (py3.11+); only requests needs pip.
  if python3 -c 'import requests' >/dev/null 2>&1; then return; fi
  log "installing python deps (requests)"
  python3 -m pip install -q -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null \
    || python3 -m pip install -q --break-system-packages \
         -r "$SCRIPT_DIR/requirements.txt" \
    || die "python deps install failed (requests)."
}

# -------------------------------------------------------------------- incus
apt_has_pkg() { apt-cache show "$1" >/dev/null 2>&1; }

setup_zabbly_apt() {
  # Debian 12 / Ubuntu 22 and older have no `incus` in the distro repos.
  # Add the upstream Zabbly repo (the method Incus documents itself).
  log "incus not in distro repos — adding upstream Zabbly repo"
  pm_install curl ca-certificates gpg
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc \
    || die "could not fetch Zabbly signing key (no internet?)."
  local codename arch
  codename="$(os_field VERSION_CODENAME)"
  arch="$(dpkg --print-architecture)"
  [[ -n "$codename" ]] || die "cannot determine distro codename for Zabbly repo."
  cat > /etc/apt/sources.list.d/zabbly-incus-stable.sources <<EOF
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: ${codename}
Components: main
Architectures: ${arch}
Signed-By: /etc/apt/keyrings/zabbly.asc
EOF
  apt-get update -y
}

ensure_incus() {
  if command -v incus >/dev/null 2>&1; then
    log "incus present: $(incus version 2>/dev/null | head -1 || echo installed)"
    return
  fi
  case "$PM" in
    apt-get)
      pm_refresh
      apt_has_pkg incus || setup_zabbly_apt
      pm_install incus
      ;;
    dnf|yum)
      # Fedora ships incus in its main repos; RHEL-family (Alma/Rocky/CentOS)
      # get it from EPEL.
      if [[ "$(os_field ID)" != "fedora" ]]; then
        pm_install epel-release \
          || warn "epel-release install failed (already enabled?)"
      fi
      pm_install incus
      ;;
    pacman)
      pm_refresh
      pm_install incus
      ;;
  esac
  command -v incus >/dev/null 2>&1 || die "incus install failed."
}

ensure_incus_running() {
  command -v systemctl >/dev/null 2>&1 || return 0
  # Socket-activated on most distros; fall back to the service unit.
  systemctl enable --now incus.socket  >/dev/null 2>&1 || true
  systemctl enable --now incus.service >/dev/null 2>&1 \
    || systemctl start incus >/dev/null 2>&1 || true
}

wait_incus_daemon() {
  for _ in $(seq 1 30); do
    incus info >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

incus_initialised() {
  # The harness `incus init` relies on the default profile carrying a root
  # disk, which needs at least one storage pool. Both must exist.
  incus storage list --format csv 2>/dev/null | grep -q . || return 1
  incus profile device get default root pool >/dev/null 2>&1 || return 1
}

ensure_incus_init() {
  if incus_initialised; then
    log "incus already initialised (storage pool + default profile present)"
    return
  fi
  log "initialising incus (minimal: dir storage + default profile)"
  incus admin init --minimal
}

# ------------------------------------------------------------------- run it
detect_pm
log "package manager: $PM  ·  distro: $(os_field ID) $(os_field VERSION_ID)"
ensure_python
ensure_incus
ensure_incus_running
wait_incus_daemon \
  || die "incus daemon not responding (check: systemctl status incus)."
ensure_incus_init
ensure_py_deps
log "backend ready: $(incus version 2>/dev/null | head -1)"
log "run the matrix with:  sudo ./run.sh"
