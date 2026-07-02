#!/usr/bin/env bash
#
# setup-fedora-server.sh — One-shot Fedora/RHEL server installer for vpn-ui
#
# Does the complete server setup in a single, resumable, idempotent run:
#   1. Pre-flight checks (root, OS, kernel)
#   2. Ensure required kernel modules — auto-recovers minimal/cloud kernels by
#      installing a kernel + modules and, if a reboot is required, continuing
#      automatically after the reboot
#   3. VPN backend (delegates to setup-vpn-backend.sh: xl2tpd/libreswan/pptpd/
#      openvpn/nftables + libreswan MODP1024 rebuild)
#   4. Install Go (from upstream — Fedora's package is older than go.mod needs)
#   5. Build the panel binary (CGO/SQLite)
#   6. Install Xray-core
#   7. Deploy + enable the x-ui systemd service
#   8. Open firewalld ports
#   9. SELinux check + verification summary
#
# There are NO command-line flags. Anything the script needs, it asks you for
# as it runs. Safe to re-run: every step checks its own state before acting.
#
# Usage:
#   sudo ./setup-fedora-server.sh
#
# When it needs to continue after a reboot it re-runs itself from a one-shot
# systemd unit (no terminal); in that mode it uses the answers you already gave
# and safe defaults instead of prompting.
#

set -Eeuo pipefail

# --------------------------------------------------------------------------- #
#  Configuration
# --------------------------------------------------------------------------- #

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

INSTALL_DIR="/usr/local/x-ui"
DEFAULT_PANEL_PORT="2053"
SUB_PORT="2096"
XRAY_VERSION="25.1.1"
GO_VERSION="1.26.2"                           # must satisfy go.mod's `go` directive
LOG_FILE="/var/log/vpn-ui-setup.log"
STATE_DIR="/var/lib/vpn-ui-setup"
RESUME_UNIT="vpn-ui-setup-resume.service"
MAX_REBOOTS=1                                 # boot-loop guard for kernel modules

PANEL_PORT="$DEFAULT_PANEL_PORT"              # resolved in ask_settings()

# Interactive only when stdin is a real terminal. The post-reboot systemd unit
# runs without a TTY, so it automatically takes the non-interactive path.
INTERACTIVE=false
[[ -t 0 ]] && INTERACTIVE=true

KERNEL_MODULES=(
    ppp_generic       # PPP core
    l2tp_ppp          # L2TP
    nf_conntrack_pptp # PPTP
    ip_gre            # PPTP/GRE
    ppp_mppe          # MPPE
    nf_tproxy_ipv4    # TPROXY (L2TP/PPTP -> Xray)
    af_key            # IPsec
)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --------------------------------------------------------------------------- #
#  Logging + error handling
# --------------------------------------------------------------------------- #

log()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR]${NC}   $*"; }
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
step()  { echo -e "\n${BLUE}==> $*${NC}"; }

CURRENT_STEP="startup"

on_error() {
    local exit_code=$?
    local line=${1:-?}
    echo ""
    err "Setup failed during: ${CURRENT_STEP}"
    err "  (exit ${exit_code} at line ${line}: ${BASH_COMMAND})"
    echo ""
    warn "This script is idempotent — fix the issue above and re-run:"
    warn "    sudo ${SCRIPT_PATH}"
    warn "Completed steps will be skipped automatically."
    exit "$exit_code"
}
trap 'on_error $LINENO' ERR

die() { err "$@"; exit 1; }

# confirm "question" "default(Y|N)" -> 0 for yes. Non-interactive uses default.
confirm() {
    local prompt="$1" default="${2:-N}"
    if [[ "$INTERACTIVE" != true ]]; then
        [[ "${default^^}" == "Y" ]]
        return
    fi
    local hint="[y/N]"; [[ "${default^^}" == "Y" ]] && hint="[Y/n]"
    local answer
    read -r -p "$(echo -e "${YELLOW}?${NC} ${prompt} ${hint} ")" answer || answer=""
    answer="${answer:-$default}"
    [[ "${answer,,}" == "y" ]]
}

# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #

arch_go() {
    case "$(uname -m)" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        *) die "Unsupported architecture for Go: $(uname -m)" ;;
    esac
}

fetch() {  # fetch URL OUTFILE — with retries
    curl -fSL --retry 3 --retry-delay 3 --connect-timeout 20 -o "$2" "$1"
}

version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

# --------------------------------------------------------------------------- #
#  1. Pre-flight + settings
# --------------------------------------------------------------------------- #

preflight() {
    CURRENT_STEP="pre-flight checks"
    step "Pre-flight checks"

    [[ $EUID -eq 0 ]] || die "Run as root (or via sudo)."

    [[ -f /etc/os-release ]] && . /etc/os-release || die "/etc/os-release missing."
    info "OS: ${PRETTY_NAME:-unknown}"

    case "${ID:-}" in
        fedora|rhel|centos|almalinux|rocky|ol|amzn) : ;;
        *) die "This installer targets Fedora/RHEL-family (dnf). Detected: ${ID:-unknown}. Use install.sh for other distros." ;;
    esac
    command -v dnf &>/dev/null || die "dnf not found."

    [[ -f "$SCRIPT_DIR/setup-vpn-backend.sh" ]] || die "setup-vpn-backend.sh not found next to this script ($SCRIPT_DIR). Run from the vpn-ui repo."
    [[ -f "$SCRIPT_DIR/main.go" ]] || die "main.go not found in $SCRIPT_DIR. Run from the vpn-ui repo."

    local arch; arch="$(uname -m)"
    [[ "$arch" == "x86_64" || "$arch" == "aarch64" ]] || warn "Untested architecture: $arch"

    local kver; kver="$(uname -r | cut -d. -f1)"
    [[ "$kver" -ge 4 ]] || die "Kernel $(uname -r) too old (need 4.x+ for nftables/TPROXY)."
    info "Kernel: $(uname -r)"

    mkdir -p "$STATE_DIR"
    dnf install -y -q curl tar unzip git >/dev/null 2>&1 || dnf install -y curl tar unzip git
    log "Pre-flight passed"
}

# Ask up-front for anything the later (possibly post-reboot, non-interactive)
# steps need, and persist it so a resumed run reuses the same answers.
ask_settings() {
    CURRENT_STEP="settings"
    local pf="$STATE_DIR/panel-port"

    if [[ "$INTERACTIVE" == true ]]; then
        step "Settings"
        local ans=""
        while true; do
            read -r -p "$(echo -e "${YELLOW}?${NC} Panel web port [${DEFAULT_PANEL_PORT}]: ")" ans || ans=""
            ans="${ans:-$DEFAULT_PANEL_PORT}"
            if [[ "$ans" =~ ^[0-9]+$ ]] && (( ans >= 1 && ans <= 65535 )); then break; fi
            warn "Enter a port between 1 and 65535."
        done
        PANEL_PORT="$ans"
        echo "$PANEL_PORT" > "$pf"
        info "Panel port set to ${PANEL_PORT} (used for the firewall rule)."
    else
        # Non-interactive / resumed run: reuse the earlier answer, else default.
        [[ -f "$pf" ]] && PANEL_PORT="$(cat "$pf" 2>/dev/null || echo "$DEFAULT_PANEL_PORT")"
        PANEL_PORT="${PANEL_PORT:-$DEFAULT_PANEL_PORT}"
    fi
}

# --------------------------------------------------------------------------- #
#  2. Kernel modules (minimal/cloud-kernel recovery + reboot-resume)
# --------------------------------------------------------------------------- #

try_load_modules() {
    local failed=() mod
    for mod in "${KERNEL_MODULES[@]}"; do
        if lsmod | grep -qw "$mod"; then continue; fi
        modprobe "$mod" 2>/dev/null || failed+=("$mod")
    done
    [[ ${#failed[@]} -gt 0 ]] && printf '%s\n' "${failed[@]}"
    return 0
}

persist_modules() { printf '%s\n' "${KERNEL_MODULES[@]}" > /etc/modules-load.d/vpn-ui.conf; }

setup_reboot_resume() {
    # One-shot unit that re-runs this script after reboot and removes itself.
    # ExecStartPre deletes the unit file first, so a crash can't cause a loop.
    info "Configuring automatic resume after reboot (logged to $LOG_FILE)..."
    cat > "/etc/systemd/system/$RESUME_UNIT" << EOF
[Unit]
Description=Resume vpn-ui Fedora setup after reboot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/usr/bin/rm -f /etc/systemd/system/$RESUME_UNIT
ExecStart=/bin/bash -c '"$SCRIPT_PATH" >> "$LOG_FILE" 2>&1; systemctl disable $RESUME_UNIT'
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$RESUME_UNIT" >/dev/null 2>&1
    log "Resume unit installed — setup will continue after the next boot"
}

# Called when modules still won't load: offer reboot, but never loop forever.
handle_unloadable_modules() {
    local failed_list="$1"
    local attempts_file="$STATE_DIR/reboot-attempts"
    local attempts=0
    [[ -f "$attempts_file" ]] && attempts="$(cat "$attempts_file" 2>/dev/null || echo 0)"

    if [[ "$attempts" -ge "$MAX_REBOOTS" ]]; then
        warn "Already rebooted for kernel modules ${attempts}x — not rebooting again (boot-loop guard)."
        warn "Still unavailable: ${failed_list}"
        if confirm "Continue setup anyway? (L2TP/PPTP may not work until the kernel is fixed)" "Y"; then
            rm -f "$attempts_file"
            return 0
        fi
        die "Aborted. Fix the kernel/modules and re-run: sudo $SCRIPT_PATH"
    fi

    echo $((attempts + 1)) > "$attempts_file"
    setup_reboot_resume
    if confirm "Reboot now to load kernel modules and continue automatically?" "Y"; then
        info "Rebooting in 5s... (setup resumes on boot; progress in $LOG_FILE)"
        sleep 5
        systemctl reboot
        exit 0
    fi
    warn "Reboot skipped. Run 'sudo reboot' when ready — setup auto-resumes on boot."
    exit 0
}

ensure_kernel_modules() {
    CURRENT_STEP="kernel modules"
    step "Ensuring kernel modules"

    local attempts_file="$STATE_DIR/reboot-attempts"
    local failed; mapfile -t failed < <(try_load_modules)
    if [[ ${#failed[@]} -eq 0 ]]; then
        persist_modules
        rm -f "$attempts_file"
        log "All kernel modules loaded"
        return
    fi

    warn "Modules not loadable on the running kernel: ${failed[*]}"
    info "Installing modules for the running kernel..."
    dnf install -y "kernel-modules-extra-$(uname -r)" >/dev/null 2>&1 || true
    mapfile -t failed < <(try_load_modules)
    if [[ ${#failed[@]} -eq 0 ]]; then
        persist_modules; rm -f "$attempts_file"
        log "Kernel modules installed and loaded (no reboot needed)"
        return
    fi

    persist_modules
    echo ""
    warn "These modules could not be loaded on the current kernel: ${failed[*]}"
    warn "This is typical of minimal/cloud images. Installing a full kernel usually fixes it,"
    warn "but that needs a reboot. On a container or a host where you manage the kernel"
    warn "yourself, you may prefer to skip this."
    echo ""

    if confirm "Install a full kernel + modules and reboot to fix this?" "Y"; then
        info "Installing kernel + modules (a reboot will be required)..."
        dnf install -y kernel kernel-modules-extra >/dev/null 2>&1 || warn "Could not install kernel packages"
        mapfile -t failed < <(try_load_modules)
        if [[ ${#failed[@]} -eq 0 ]]; then
            persist_modules; rm -f "$attempts_file"
            log "Kernel modules loaded (no reboot needed)"
            return
        fi
        handle_unloadable_modules "${failed[*]}"
    else
        if confirm "Continue without them? (L2TP/PPTP may not work)" "Y"; then
            warn "Continuing without kernel modules: ${failed[*]}"
            return
        fi
        die "Aborted. Load the modules (or install a suitable kernel) and re-run."
    fi
}

# --------------------------------------------------------------------------- #
#  3. VPN backend
# --------------------------------------------------------------------------- #

run_backend() {
    CURRENT_STEP="VPN backend (setup-vpn-backend.sh)"
    step "Installing VPN backend"

    # Pre-remove StrongSwan so the backend's own prompt is a no-op
    if rpm -q strongswan &>/dev/null; then
        info "Removing StrongSwan (incompatible with Windows L2TP)..."
        dnf remove -y strongswan >/dev/null 2>&1 || true
    fi

    chmod +x "$SCRIPT_DIR/setup-vpn-backend.sh"
    # Feed an endless "y" stream so the delegated backend never blocks — kernel
    # modules and StrongSwan are already handled above.
    "$SCRIPT_DIR/setup-vpn-backend.sh" install < <(yes)
    log "VPN backend installed"
}

# --------------------------------------------------------------------------- #
#  4. Go toolchain
# --------------------------------------------------------------------------- #

ensure_go() {
    CURRENT_STEP="Go toolchain"
    step "Ensuring Go >= $GO_VERSION"

    local go_bin=""
    command -v go &>/dev/null && go_bin="$(command -v go)"
    [[ -x /usr/local/go/bin/go ]] && go_bin="/usr/local/go/bin/go"

    if [[ -n "$go_bin" ]]; then
        local have; have="$("$go_bin" version | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | sed 's/go//')"
        if [[ -n "$have" ]] && version_ge "$have" "$GO_VERSION"; then
            export PATH="$(dirname "$go_bin"):$PATH"
            log "Go $have present ($go_bin)"
            return
        fi
        info "Found Go ${have:-unknown}, need >= $GO_VERSION — installing upstream Go"
    else
        info "Go not found — installing upstream Go $GO_VERSION"
    fi

    dnf install -y gcc glibc-devel >/dev/null 2>&1 || dnf install -y gcc glibc-devel
    local tarball="/tmp/go${GO_VERSION}.tar.gz"
    info "Downloading Go $GO_VERSION..."
    fetch "https://go.dev/dl/go${GO_VERSION}.linux-$(arch_go).tar.gz" "$tarball"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tarball"
    rm -f "$tarball"
    export PATH="/usr/local/go/bin:$PATH"
    command -v go &>/dev/null || die "Go install failed."
    log "Installed $(go version)"
}

# --------------------------------------------------------------------------- #
#  5. Build the panel
# --------------------------------------------------------------------------- #

build_panel() {
    CURRENT_STEP="building panel binary"
    step "Building the panel binary"

    if [[ -x "$INSTALL_DIR/x-ui" ]] && systemctl is-active --quiet x-ui 2>/dev/null; then
        if ! confirm "Panel already built and running. Rebuild it?" "N"; then
            log "Keeping the existing panel binary"
            return
        fi
    fi

    info "Compiling (CGO enabled for SQLite)... this can take a couple of minutes"
    if ! ( cd "$SCRIPT_DIR" && CGO_ENABLED=1 go build -o x-ui main.go ); then
        # A 403/timeout from proxy.golang.org (rate-limiting) does not fall back
        # to source automatically — retry fetching modules directly from origin.
        warn "Build failed — retrying with GOPROXY=direct (fetch modules from source)..."
        ( cd "$SCRIPT_DIR" && CGO_ENABLED=1 GOPROXY=direct GOSUMDB=off go build -o x-ui main.go )
    fi
    [[ -x "$SCRIPT_DIR/x-ui" ]] || die "Build produced no x-ui binary."
    log "Panel built: $SCRIPT_DIR/x-ui"
}

# --------------------------------------------------------------------------- #
#  6. Xray-core
# --------------------------------------------------------------------------- #

install_xray() {
    CURRENT_STEP="installing Xray"
    step "Installing Xray-core $XRAY_VERSION"

    local bin="$INSTALL_DIR/bin/xray-linux-amd64" zipname="Xray-linux-64.zip"
    if [[ "$(uname -m)" == "aarch64" ]]; then
        bin="$INSTALL_DIR/bin/xray-linux-arm64"; zipname="Xray-linux-arm64-v8a.zip"
    fi

    if [[ -x "$bin" ]]; then
        log "Xray already installed ($bin)"
        return
    fi

    mkdir -p "$INSTALL_DIR/bin"
    local zipfile="/tmp/xray.zip"
    info "Downloading Xray $XRAY_VERSION..."
    fetch "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/${zipname}" "$zipfile"
    rm -rf /tmp/xray && mkdir -p /tmp/xray
    unzip -o "$zipfile" -d /tmp/xray >/dev/null
    cp /tmp/xray/xray "$bin"
    chmod +x "$bin"
    cp /tmp/xray/geo*.dat "$INSTALL_DIR/bin/" 2>/dev/null || true
    rm -rf /tmp/xray "$zipfile"
    log "Xray installed: $bin"
}

# --------------------------------------------------------------------------- #
#  7. Deploy + systemd
# --------------------------------------------------------------------------- #

deploy_service() {
    CURRENT_STEP="deploying systemd service"
    step "Deploying the panel service"

    mkdir -p "$INSTALL_DIR" /var/log/x-ui

    # Nothing to do if the deployed binary already matches and the service is up.
    if systemctl is-active --quiet x-ui 2>/dev/null \
        && [[ -x "$INSTALL_DIR/x-ui" ]] && cmp -s "$SCRIPT_DIR/x-ui" "$INSTALL_DIR/x-ui"; then
        log "Panel binary already deployed and running — skipping"
        return
    fi

    # Stop first — overwriting a running binary fails with "Text file busy".
    systemctl stop x-ui 2>/dev/null || true
    cp "$SCRIPT_DIR/x-ui" "$INSTALL_DIR/x-ui"
    chmod +x "$INSTALL_DIR/x-ui"

    cat > /etc/systemd/system/x-ui.service << EOF
[Unit]
Description=x-ui
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/x-ui run
WorkingDirectory=$INSTALL_DIR
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now x-ui >/dev/null 2>&1 || systemctl enable --now x-ui

    sleep 2
    if systemctl is-active --quiet x-ui; then
        log "Panel service is running"
    else
        warn "Panel service did not start — check: journalctl -u x-ui -n 50"
    fi
}

# --------------------------------------------------------------------------- #
#  8. Firewall
# --------------------------------------------------------------------------- #

configure_firewall() {
    CURRENT_STEP="firewall"
    step "Configuring firewalld"

    local ports_note="${PANEL_PORT}/tcp, 1701/udp, 500/udp, 4500/udp, 1723/tcp, 1194/udp+tcp"

    if ! command -v firewall-cmd &>/dev/null; then
        if confirm "firewalld is not installed. Install it and open the VPN ports?" "Y"; then
            dnf install -y firewalld >/dev/null 2>&1 || { warn "Could not install firewalld; open manually: $ports_note"; return; }
        else
            warn "Skipping firewall. Open these ports yourself: $ports_note"
            return
        fi
    fi
    systemctl enable --now firewalld >/dev/null 2>&1 || true

    if ! firewall-cmd --state 2>/dev/null | grep -q running; then
        warn "firewalld not running — open these ports manually: $ports_note"
        return
    fi

    local tcp=("${PANEL_PORT}" "${SUB_PORT}" 1723 1194) udp=(1701 500 4500 1194) p
    for p in "${tcp[@]}"; do firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null 2>&1 || true; done
    for p in "${udp[@]}"; do firewall-cmd --permanent --add-port="${p}/udp" >/dev/null 2>&1 || true; done
    firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    log "Opened ports: ${PANEL_PORT}/tcp (panel), 1701/500/4500 udp (L2TP/IPsec), 1723/tcp (PPTP), 1194 (OpenVPN)"
}

# --------------------------------------------------------------------------- #
#  9. SELinux note
# --------------------------------------------------------------------------- #

selinux_note() {
    command -v getenforce &>/dev/null || return 0
    [[ "$(getenforce 2>/dev/null || echo Disabled)" == "Enforcing" ]] || return 0
    echo ""
    warn "SELinux is Enforcing. The source-built xl2tpd and pppd/RADIUS hooks may trigger denials."
    warn "If L2TP/PPTP clients fail to connect, check:  ausearch -m avc -ts recent"
    warn "Temporary diagnostic:  setenforce 0   (re-enable with setenforce 1)"
}

# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #

main() {
    echo ""
    echo "================================================================"
    echo "  vpn-ui — Fedora/RHEL one-shot server installer"
    echo "  L2TP/IPsec + PPTP + OpenVPN + Xray panel"
    echo "================================================================"

    preflight
    ask_settings
    ensure_kernel_modules      # may reboot + auto-resume
    run_backend
    ensure_go
    build_panel
    install_xray
    deploy_service
    configure_firewall

    local ip; ip="$(hostname -I 2>/dev/null | awk '{print $1}')"; ip="${ip:-YOUR_SERVER_IP}"
    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  vpn-ui — Fedora setup complete${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
    echo "  Panel:  http://${ip}:${PANEL_PORT}   (default login: admin / admin)"
    echo "  Change the default credentials immediately."
    echo ""
    echo "  Service status:  systemctl status x-ui"
    echo "  Panel logs:      journalctl -u x-ui -f"
    echo "  Update backend:  sudo ${SCRIPT_DIR}/setup-vpn-backend.sh update"
    echo ""
    echo -e "${BLUE}================================================================${NC}"
    selinux_note
}

main
