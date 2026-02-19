#!/usr/bin/env bash
#
# setup-vpn-backend.sh — Install and configure the VPN backend for vpn-ui (3x-ui fork)
#
# Supports: L2TP/IPsec, PPTP, OpenVPN
# Target OS: Debian 12+ / Ubuntu 22.04+
#
# Usage:
#   chmod +x setup-vpn-backend.sh
#   sudo ./setup-vpn-backend.sh
#
# This script is idempotent — safe to run multiple times.
# It will NOT overwrite existing VPN config files (those are managed by the panel at runtime).
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
#  Summary
# --------------------------------------------------------------------------- #

print_summary() {
    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  VPN Backend Setup Complete${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
    echo "  The following VPN services are installed and ready:"
    echo ""
    echo "    L2TP/IPsec  — xl2tpd + Libreswan + pppd"
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
#  Main
# --------------------------------------------------------------------------- #

main() {
    echo ""
    echo "================================================================"
    echo "  vpn-ui — VPN Backend Setup Script"
    echo "  L2TP/IPsec + PPTP + OpenVPN"
    echo "================================================================"
    echo ""

    preflight
    install_packages
    check_strongswan_conflict
    load_kernel_modules
    configure_sysctl
    create_directories
    configure_services
    verify
    print_summary
}

main "$@"
