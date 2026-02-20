#!/usr/bin/env bash
#
# setup-vpn-backend.sh — Install, update, or uninstall the VPN backend for vpn-ui (3x-ui fork)
#
# Supports: L2TP/IPsec, PPTP, OpenVPN
# Target OS: Debian 12+ / Ubuntu 22.04+
#
# Usage:
#   sudo ./setup-vpn-backend.sh install     # First-time setup (default)
#   sudo ./setup-vpn-backend.sh update      # Re-apply config on existing install
#   sudo ./setup-vpn-backend.sh uninstall   # Remove VPN backend completely
#
# The install and update commands are idempotent — safe to run multiple times.
#

set -euo pipefail

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

REQUIRED_PACKAGES=(
    # L2TP/IPsec
    xl2tpd
    ppp
    libreswan
    # PPTP
    pptpd
    # OpenVPN
    openvpn
    # Firewall & networking
    nftables
    iproute2
    iptables          # legacy cleanup only; nftables is primary
    # RADIUS (pppd radius plugin — shipped with ppp on Debian)
    libradcli4
)

# Packages installed only for Libreswan rebuild (can be removed after)
BUILD_PACKAGES=(
    dpkg-dev
    build-essential
    libnspr4-dev
    libnss3-dev
    libnss3-tools
    libpam0g-dev
    libcap-ng-dev
    libcurl4-openssl-dev
    libldap2-dev
    libunbound-dev
    libevent-dev
    libsystemd-dev
    xmlto
    bison
    flex
    pkg-config
    libaudit-dev
    libselinux1-dev
)

KERNEL_MODULES=(
    # PPP core
    ppp_generic
    # L2TP
    l2tp_ppp
    # PPTP / MPPE
    nf_conntrack_pptp
    ip_gre
    ppp_mppe
    # TPROXY (routes L2TP/PPTP traffic through Xray)
    nf_tproxy_ipv4
    # IPsec
    af_key
)

SYSCTL_PARAMS=(
    "net.ipv4.ip_forward=1"
)

REQUIRED_DIRS=(
    /etc/ppp/radius
    /etc/xl2tpd
    /etc/x-ui
    /var/run/openvpn
    /var/log/x-ui
    /usr/local/x-ui/bin
)

# Files and directories created by the panel at runtime
PANEL_GENERATED_FILES=(
    /etc/ipsec.conf
    /etc/ipsec.secrets
    /etc/xl2tpd/xl2tpd.conf
    /etc/pptpd.conf
)
PANEL_GENERATED_GLOBS=(
    "/etc/ppp/options.xl2tpd-*"
    "/etc/ppp/pptpd-options-*"
    "/etc/ppp/radius/l2tp-*.conf"
    "/etc/ppp/radius/pptp-*.conf"
    "/etc/ppp/radius/openvpn-*.conf"
    "/etc/ppp/ip-up.d/vpn-*"
    "/etc/ppp/ip-down.d/vpn-*"
    "/etc/openvpn/server-*"
    "/etc/systemd/system/openvpn-server@*"
    "/var/run/openvpn/*"
)

SETUP_CONFIG_FILES=(
    /etc/modules-load.d/vpn-ui.conf
    /etc/sysctl.d/99-vpn-ui.conf
    /etc/apt/preferences.d/libreswan
)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #

log()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR]${NC}   $*"; }
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
step()  { echo -e "\n${BLUE}==> $*${NC}"; }

die() {
    err "$@"
    exit 1
}

# --------------------------------------------------------------------------- #
#  Pre-flight checks
# --------------------------------------------------------------------------- #

preflight() {
    step "Pre-flight checks"

    # Must be root
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (or via sudo)."
    fi

    # Detect OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        info "Detected OS: $PRETTY_NAME"
    else
        warn "Cannot detect OS — /etc/os-release not found. Proceeding anyway."
    fi

    # Must be Debian/Ubuntu-based (apt required)
    if ! command -v apt-get &>/dev/null; then
        die "apt-get not found. This script requires a Debian/Ubuntu-based system."
    fi

    # Check architecture
    local arch
    arch=$(uname -m)
    if [[ "$arch" != "x86_64" && "$arch" != "aarch64" ]]; then
        warn "Untested architecture: $arch. This script is designed for x86_64/aarch64."
    fi

    # Check kernel version (need 4.x+ for nftables/TPROXY)
    local kver
    kver=$(uname -r | cut -d. -f1)
    if [[ "$kver" -lt 4 ]]; then
        die "Kernel $(uname -r) is too old. Minimum required: 4.x (for nftables/TPROXY support)."
    fi
    info "Kernel: $(uname -r)"

    log "Pre-flight checks passed"
}

# --------------------------------------------------------------------------- #
#  Package installation
# --------------------------------------------------------------------------- #

install_packages() {
    step "Installing system packages"

    # Refresh package index (but don't fail if a single source is unavailable)
    info "Updating package index..."
    apt-get update -qq || warn "apt-get update had warnings (continuing)"

    local to_install=()
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            log "$pkg — already installed"
        else
            to_install+=("$pkg")
        fi
    done

    if [[ ${#to_install[@]} -eq 0 ]]; then
        log "All required packages are already installed"
        return
    fi

    info "Installing: ${to_install[*]}"
    if ! apt-get install -y "${to_install[@]}"; then
        die "Failed to install packages. Check apt output above."
    fi

    log "Packages installed successfully"
}

# --------------------------------------------------------------------------- #
#  Kernel modules
# --------------------------------------------------------------------------- #

load_kernel_modules() {
    step "Loading kernel modules"

    local failed=()
    for mod in "${KERNEL_MODULES[@]}"; do
        if lsmod | grep -qw "$mod"; then
            log "$mod — already loaded"
        elif modprobe "$mod" 2>/dev/null; then
            log "$mod — loaded"
        else
            failed+=("$mod")
            warn "$mod — FAILED to load"
        fi
    done

    if [[ ${#failed[@]} -gt 0 ]]; then
        echo ""
        warn "The following kernel modules could not be loaded:"
        for mod in "${failed[@]}"; do
            warn "  - $mod"
        done
        echo ""
        warn "This usually means your kernel is a minimal/cloud variant."
        warn "Fix: apt-get install -y linux-image-amd64 && reboot"
        echo ""
        read -r -p "Continue anyway? [y/N] " answer
        if [[ "${answer,,}" != "y" ]]; then
            die "Aborted. Install the full kernel and try again."
        fi
    fi

    # Persist modules across reboots
    local modules_file="/etc/modules-load.d/vpn-ui.conf"
    if [[ ! -f "$modules_file" ]] || ! diff -q <(printf '%s\n' "${KERNEL_MODULES[@]}" | sort) <(sort "$modules_file") &>/dev/null; then
        info "Writing $modules_file for boot-time loading..."
        printf '%s\n' "${KERNEL_MODULES[@]}" > "$modules_file"
        log "Kernel modules will load automatically on boot"
    else
        log "Module persistence already configured"
    fi
}

# --------------------------------------------------------------------------- #
#  sysctl (IP forwarding)
# --------------------------------------------------------------------------- #

configure_sysctl() {
    step "Configuring sysctl parameters"

    local sysctl_file="/etc/sysctl.d/99-vpn-ui.conf"
    local changed=false

    for param in "${SYSCTL_PARAMS[@]}"; do
        local key="${param%%=*}"
        local val="${param##*=}"
        local current
        current=$(sysctl -n "$key" 2>/dev/null || echo "")

        if [[ "$current" == "$val" ]]; then
            log "$key = $val — already set"
        else
            info "Setting $key = $val (was: $current)"
            sysctl -w "$param" >/dev/null
            changed=true
        fi
    done

    # Persist
    if [[ "$changed" == true ]] || [[ ! -f "$sysctl_file" ]]; then
        printf '%s\n' "${SYSCTL_PARAMS[@]}" > "$sysctl_file"
        log "sysctl parameters persisted to $sysctl_file"
    fi
}

# --------------------------------------------------------------------------- #
#  Directories
# --------------------------------------------------------------------------- #

create_directories() {
    step "Creating required directories"

    for dir in "${REQUIRED_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            log "$dir — exists"
        else
            mkdir -p "$dir"
            log "$dir — created"
        fi
    done
}

# --------------------------------------------------------------------------- #
#  Service configuration
# --------------------------------------------------------------------------- #

configure_services() {
    step "Configuring service defaults"

    # Disable auto-start for VPN daemons — the panel manages their lifecycle.
    # We don't want them starting on boot with stale/missing configs.
    local services=(xl2tpd pptpd)
    for svc in "${services[@]}"; do
        if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
            info "Disabling auto-start for $svc (panel manages it)"
            systemctl disable "$svc" 2>/dev/null || true
            # Stop if running with no panel-generated config
            if systemctl is-active "$svc" &>/dev/null && [[ ! -f /etc/xl2tpd/xl2tpd.conf ]] && [[ "$svc" == "xl2tpd" ]]; then
                systemctl stop "$svc" 2>/dev/null || true
            fi
            if systemctl is-active "$svc" &>/dev/null && [[ ! -f /etc/pptpd.conf ]] && [[ "$svc" == "pptpd" ]]; then
                systemctl stop "$svc" 2>/dev/null || true
            fi
        fi
        log "$svc — auto-start disabled (panel-managed)"
    done

    # Ensure nftables service is enabled (the panel loads rules atomically, but
    # the nftables service ensures the kernel subsystem is initialized)
    if ! systemctl is-enabled nftables &>/dev/null 2>&1; then
        systemctl enable nftables 2>/dev/null || true
        log "nftables — enabled"
    else
        log "nftables — already enabled"
    fi

    # Ensure ipsec (Libreswan) does NOT auto-start — panel manages it
    if systemctl is-enabled ipsec &>/dev/null 2>&1; then
        info "Disabling auto-start for ipsec (panel manages it)"
        systemctl disable ipsec 2>/dev/null || true
        log "ipsec — auto-start disabled (panel-managed)"
    else
        log "ipsec — auto-start already disabled"
    fi
}

# --------------------------------------------------------------------------- #
#  Rebuild Libreswan with ALL_ALGS=true (enables modp1024/DH2 for MikroTik)
# --------------------------------------------------------------------------- #

rebuild_libreswan() {
    step "Checking Libreswan for legacy algorithm support (modp1024/DH2)"

    # Check if Libreswan is installed
    if ! command -v ipsec &>/dev/null; then
        warn "Libreswan not installed — skipping rebuild"
        return
    fi

    # Check if modp1024 is already available
    if ipsec pluto --selftest 2>&1 | grep -q 'MODP1024'; then
        log "Libreswan already has MODP1024 (DH2) support"
        return
    fi

    info "Libreswan lacks MODP1024 (DH2) — rebuilding with ALL_ALGS=true"
    info "This enables legacy DH groups for MikroTik and older clients"

    # Install build dependencies
    info "Installing build dependencies..."
    apt-get install -y -qq dpkg-dev >/dev/null 2>&1 || true
    apt-get build-dep -y -qq libreswan >/dev/null 2>&1 || {
        warn "Could not install Libreswan build dependencies"
        warn "MikroTik and other legacy devices needing modp1024 will not work"
        return
    }

    # Download and extract source
    local build_dir
    build_dir=$(mktemp -d /tmp/libreswan-build.XXXXXX)
    info "Building in $build_dir (this may take a few minutes)..."
    cd "$build_dir"
    apt-get source --download-only libreswan >/dev/null 2>&1 || {
        warn "Could not download Libreswan source"
        cd /
        rm -rf "$build_dir"
        return
    }
    dpkg-source -x libreswan_*.dsc libreswan-src >/dev/null 2>&1

    # Patch debian/rules to add ALL_ALGS=true
    if [[ -f libreswan-src/debian/rules ]]; then
        perl -i -pe 's|(ARCH=\$\(DEB_HOST_ARCH\) \\)|$1\n\t\tALL_ALGS=true \\|' \
            libreswan-src/debian/rules
    fi

    # Build (skip tests — algparse test suite has known failures with ALL_ALGS)
    cd libreswan-src
    if DEB_BUILD_OPTIONS=nocheck dpkg-buildpackage -b -uc -us -j"$(nproc)" >/dev/null 2>&1; then
        # Install the rebuilt package
        dpkg -i ../libreswan_*_"$(dpkg --print-architecture)".deb >/dev/null 2>&1
        log "Libreswan rebuilt and installed with ALL_ALGS=true"

        # Verify
        if ipsec pluto --selftest 2>&1 | grep -q 'MODP1024'; then
            log "MODP1024 (DH2) is now available"
        else
            warn "Rebuild succeeded but MODP1024 still not detected"
        fi

        # Pin the package to prevent apt from overwriting our custom build
        cat > /etc/apt/preferences.d/libreswan << 'APTPIN'
Package: libreswan
Pin: version *
Pin-Priority: -1
APTPIN
        log "Pinned libreswan package to prevent apt overwrite"
    else
        warn "Libreswan rebuild failed — continuing with stock version"
        warn "MikroTik and other legacy devices needing modp1024 will not work"
    fi

    # Cleanup
    cd /
    rm -rf "$build_dir"
}

# --------------------------------------------------------------------------- #
#  StrongSwan conflict check
# --------------------------------------------------------------------------- #

check_strongswan_conflict() {
    step "Checking for StrongSwan conflicts"

    if dpkg -l strongswan 2>/dev/null | grep -q "^ii"; then
        warn "StrongSwan is installed alongside Libreswan."
        warn "StrongSwan 6.x is INCOMPATIBLE with Windows 10/11 L2TP/IPsec."
        warn "Libreswan is the correct IPsec implementation for this panel."
        echo ""
        read -r -p "Remove StrongSwan? (recommended) [Y/n] " answer
        if [[ "${answer,,}" != "n" ]]; then
            apt-get remove -y strongswan strongswan-charon strongswan-starter 2>/dev/null || true
            log "StrongSwan removed"
        else
            warn "Keeping StrongSwan — L2TP/IPsec may not work with Windows clients"
        fi
    else
        log "No StrongSwan conflict detected"
    fi
}

# --------------------------------------------------------------------------- #
#  Verification
# --------------------------------------------------------------------------- #

verify() {
    step "Verifying installation"

    local ok=true

    # Check binaries
    local binaries=(xl2tpd pptpd openvpn ipsec nft pppd modprobe sysctl ip)
    for bin in "${binaries[@]}"; do
        if command -v "$bin" &>/dev/null; then
            log "$bin — found at $(command -v "$bin")"
        else
            err "$bin — NOT FOUND"
            ok=false
        fi
    done

    # Check pppd radius plugin
    local radius_so=""
    for path in /usr/lib/pppd/*/radius.so /usr/lib/*/pppd/*/radius.so; do
        if [[ -f "$path" ]]; then
            radius_so="$path"
            break
        fi
    done
    if [[ -n "$radius_so" ]]; then
        log "pppd radius plugin — found at $radius_so"
    else
        err "pppd radius plugin (radius.so) — NOT FOUND"
        warn "Install the ppp package or check that radius.so is available."
        ok=false
    fi

    # Check Libreswan MODP1024
    if command -v ipsec &>/dev/null; then
        if ipsec pluto --selftest 2>&1 | grep -q 'MODP1024'; then
            log "Libreswan MODP1024 (DH2) — available"
        else
            warn "Libreswan MODP1024 (DH2) — NOT available (MikroTik won't work)"
        fi
    fi

    # Check IP forwarding
    local fwd
    fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [[ "$fwd" == "1" ]]; then
        log "IP forwarding — enabled"
    else
        err "IP forwarding — disabled ($fwd)"
        ok=false
    fi

    # Check kernel modules
    local mod_ok=true
    for mod in "${KERNEL_MODULES[@]}"; do
        if ! lsmod | grep -qw "$mod"; then
            warn "$mod — not loaded"
            mod_ok=false
        fi
    done
    if [[ "$mod_ok" == true ]]; then
        log "All kernel modules loaded"
    fi

    echo ""
    if [[ "$ok" == true ]]; then
        log "Verification passed — VPN backend is ready"
    else
        warn "Some checks failed — review the output above"
    fi
}

# --------------------------------------------------------------------------- #
#  Summary (install)
# --------------------------------------------------------------------------- #

print_install_summary() {
    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  VPN Backend Setup Complete${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
    echo "  The following VPN services are installed and ready:"
    echo ""
    echo "    L2TP/IPsec  — xl2tpd + Libreswan (ALL_ALGS) + pppd"
    echo "    PPTP        — pptpd + pppd"
    echo "    OpenVPN     — openvpn (UDP + TCP)"
    echo "    RADIUS      — embedded in vpn-ui panel (127.0.0.1:1812-1813)"
    echo "    Firewall    — nftables (TPROXY + NAT + accounting)"
    echo ""
    echo "  Next steps:"
    echo ""
    echo "    1. Deploy the vpn-ui binary to /usr/local/x-ui/x-ui"
    echo "    2. Install Xray to /usr/local/x-ui/bin/xray-linux-amd64"
    echo "    3. Start the panel:  cd /usr/local/x-ui && ./x-ui run"
    echo "    4. Open http://YOUR_IP:2053 and create VPN inbounds"
    echo ""
    echo "  The panel will generate all VPN configs automatically when you"
    echo "  create inbounds. No manual config editing is needed."
    echo ""
    echo -e "${BLUE}================================================================${NC}"
}

# --------------------------------------------------------------------------- #
#  cmd: install (first-time setup)
# --------------------------------------------------------------------------- #

cmd_install() {
    echo ""
    echo "================================================================"
    echo "  vpn-ui — VPN Backend Install"
    echo "  L2TP/IPsec + PPTP + OpenVPN"
    echo "================================================================"
    echo ""

    preflight
    install_packages
    check_strongswan_conflict
    rebuild_libreswan
    load_kernel_modules
    configure_sysctl
    create_directories
    configure_services
    verify
    print_install_summary
}

# --------------------------------------------------------------------------- #
#  cmd: update (re-apply config on existing install)
# --------------------------------------------------------------------------- #

cmd_update() {
    echo ""
    echo "================================================================"
    echo "  vpn-ui — VPN Backend Update"
    echo "================================================================"
    echo ""

    preflight

    # Check that the backend was previously installed
    local missing=()
    for pkg in xl2tpd ppp libreswan pptpd openvpn; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            missing+=("$pkg")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing packages: ${missing[*]}"
        info "Installing missing packages..."
        apt-get update -qq || true
        apt-get install -y "${missing[@]}" || die "Failed to install missing packages"
    fi
    log "All required packages present"

    # Rebuild Libreswan if needed (e.g., apt upgraded and overwrote our build)
    rebuild_libreswan

    # Re-apply kernel modules (in case new ones were added)
    load_kernel_modules

    # Re-apply sysctl
    configure_sysctl

    # Ensure directories exist
    create_directories

    # Re-apply service config
    configure_services

    # If the panel is running, restart VPN services to pick up changes
    step "Restarting VPN services"
    if pgrep -x x-ui &>/dev/null; then
        info "Panel is running — restarting VPN services"

        # Restart IPsec if config exists
        if [[ -f /etc/ipsec.conf ]]; then
            ipsec restart 2>/dev/null && log "ipsec — restarted" || warn "ipsec restart failed"
            sleep 2
        fi

        # Restart xl2tpd if config exists
        if [[ -f /etc/xl2tpd/xl2tpd.conf ]]; then
            systemctl restart xl2tpd 2>/dev/null && log "xl2tpd — restarted" || warn "xl2tpd restart failed"
        fi

        # Restart pptpd if config exists
        if [[ -f /etc/pptpd.conf ]]; then
            systemctl restart pptpd 2>/dev/null && log "pptpd — restarted" || warn "pptpd restart failed"
        fi

        # Restart OpenVPN instances
        local restarted_ovpn=0
        for unit in /etc/systemd/system/openvpn-server@*.service; do
            [[ -f "$unit" ]] || continue
            local name
            name=$(basename "$unit")
            systemctl restart "$name" 2>/dev/null && log "$name — restarted" || warn "$name restart failed"
            ((restarted_ovpn++))
        done
        if [[ $restarted_ovpn -eq 0 ]]; then
            info "No OpenVPN instances found"
        fi
    else
        info "Panel is not running — skipping service restart"
        info "Services will start when the panel starts"
    fi

    verify

    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  VPN Backend Update Complete${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
    echo "  Changes applied. If the panel was running, VPN services have"
    echo "  been restarted to pick up the new configuration."
    echo ""
    echo -e "${BLUE}================================================================${NC}"
}

# --------------------------------------------------------------------------- #
#  cmd: uninstall (remove VPN backend completely)
# --------------------------------------------------------------------------- #

cmd_uninstall() {
    echo ""
    echo "================================================================"
    echo "  vpn-ui — VPN Backend Uninstall"
    echo "================================================================"
    echo ""

    # Must be root
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (or via sudo)."
    fi

    echo -e "${RED}  WARNING: This will remove all VPN backend packages, configs,${NC}"
    echo -e "${RED}  and generated files. The panel database (/etc/x-ui/x-ui.db)${NC}"
    echo -e "${RED}  and the panel binary (/usr/local/x-ui/) will NOT be removed.${NC}"
    echo ""
    read -r -p "Are you sure you want to uninstall the VPN backend? [y/N] " answer
    if [[ "${answer,,}" != "y" ]]; then
        info "Uninstall cancelled."
        exit 0
    fi

    # --- Stop services ---
    step "Stopping VPN services"

    for svc in xl2tpd pptpd ipsec; do
        if systemctl is-active "$svc" &>/dev/null 2>&1; then
            systemctl stop "$svc" 2>/dev/null && log "$svc — stopped" || warn "Failed to stop $svc"
        else
            log "$svc — not running"
        fi
    done

    # Stop OpenVPN instances
    for unit in /etc/systemd/system/openvpn-server@*.service; do
        [[ -f "$unit" ]] || continue
        local name
        name=$(basename "$unit" .service)
        systemctl stop "$name" 2>/dev/null || true
        systemctl disable "$name" 2>/dev/null || true
        rm -f "$unit"
        log "$name — stopped and removed"
    done
    systemctl daemon-reload 2>/dev/null || true

    # --- Remove panel-generated config files ---
    step "Removing panel-generated config files"

    for f in "${PANEL_GENERATED_FILES[@]}"; do
        if [[ -f "$f" ]]; then
            rm -f "$f"
            log "Removed $f"
        fi
    done

    for pattern in "${PANEL_GENERATED_GLOBS[@]}"; do
        # shellcheck disable=SC2086
        for f in $pattern; do
            [[ -e "$f" ]] || continue
            rm -rf "$f"
            log "Removed $f"
        done
    done

    # RADIUS config directory
    if [[ -d /etc/ppp/radius ]]; then
        rm -rf /etc/ppp/radius
        log "Removed /etc/ppp/radius/"
    fi

    # nftables VPN table
    if nft list table ip vpn &>/dev/null 2>&1; then
        nft delete table ip vpn 2>/dev/null && log "Removed nftables table 'ip vpn'" || warn "Failed to remove nftables vpn table"
    fi

    # --- Remove setup config files ---
    step "Removing setup config files"

    for f in "${SETUP_CONFIG_FILES[@]}"; do
        if [[ -f "$f" ]]; then
            rm -f "$f"
            log "Removed $f"
        fi
    done

    # --- Remove packages ---
    step "Removing VPN packages"

    local to_remove=()
    for pkg in xl2tpd pptpd libreswan openvpn; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            to_remove+=("$pkg")
        fi
    done

    if [[ ${#to_remove[@]} -gt 0 ]]; then
        info "Removing: ${to_remove[*]}"
        apt-get remove -y "${to_remove[@]}" 2>/dev/null || warn "Some packages could not be removed"
        log "Packages removed"
    else
        log "No VPN packages to remove"
    fi

    # Ask about purging (removes config files from packages too)
    echo ""
    read -r -p "Purge package configs too? (removes /etc defaults from packages) [y/N] " answer
    if [[ "${answer,,}" == "y" ]]; then
        apt-get purge -y "${to_remove[@]}" 2>/dev/null || true
        log "Package configs purged"
    fi

    # Ask about removing build dependencies
    echo ""
    read -r -p "Remove build dependencies (dpkg-dev, -dev packages)? [y/N] " answer
    if [[ "${answer,,}" == "y" ]]; then
        apt-get autoremove -y 2>/dev/null || true
        log "Build dependencies cleaned up"
    fi

    # --- Clean up empty directories ---
    step "Cleaning up directories"

    for dir in /etc/xl2tpd /var/run/openvpn; do
        if [[ -d "$dir" ]] && [[ -z "$(ls -A "$dir" 2>/dev/null)" ]]; then
            rmdir "$dir" 2>/dev/null && log "Removed empty $dir" || true
        fi
    done

    # --- Reload systemd ---
    systemctl daemon-reload 2>/dev/null || true

    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  VPN Backend Uninstall Complete${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
    echo "  Removed:"
    echo "    - VPN packages (xl2tpd, pptpd, libreswan, openvpn)"
    echo "    - Panel-generated configs (ipsec, xl2tpd, pptpd, openvpn, radius)"
    echo "    - Kernel module persistence (/etc/modules-load.d/vpn-ui.conf)"
    echo "    - sysctl overrides (/etc/sysctl.d/99-vpn-ui.conf)"
    echo "    - Libreswan apt pin (/etc/apt/preferences.d/libreswan)"
    echo "    - nftables VPN table"
    echo ""
    echo "  Preserved:"
    echo "    - Panel database: /etc/x-ui/x-ui.db"
    echo "    - Panel binary:   /usr/local/x-ui/"
    echo "    - Panel logs:     /var/log/x-ui/"
    echo "    - ppp package (used by pppd — shared dependency)"
    echo ""
    echo "  Note: Kernel modules are still loaded in memory until next reboot."
    echo "  IP forwarding (net.ipv4.ip_forward) may revert on reboot."
    echo ""
    echo -e "${BLUE}================================================================${NC}"
}

# --------------------------------------------------------------------------- #
#  Usage
# --------------------------------------------------------------------------- #

usage() {
    local code="${1:-0}"
    echo "Usage: $0 {install|update|uninstall}"
    echo ""
    echo "Commands:"
    echo "  install     First-time setup: install packages, configure system,"
    echo "              rebuild Libreswan with legacy cipher support (default)"
    echo "  update      Re-apply configuration on an existing install:"
    echo "              rebuild Libreswan if needed, reload modules/sysctl,"
    echo "              restart VPN services if the panel is running"
    echo "  uninstall   Remove VPN backend packages, configs, and cleanup"
    echo ""
    echo "Both install and update are idempotent — safe to run multiple times."
    exit "$code"
}

# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #

main() {
    local cmd="${1:-install}"

    case "$cmd" in
        install)    cmd_install ;;
        update)     cmd_update ;;
        uninstall)  cmd_uninstall ;;
        -h|--help|help) usage 0 ;;
        *)
            err "Unknown command: $cmd"
            usage 1
            ;;
    esac
}

main "$@"
