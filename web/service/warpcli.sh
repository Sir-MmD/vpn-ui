#!/bin/bash
#MmD

# Behave identically whether launched from an interactive root SSH shell or as a
# non-interactive child of the panel (systemd unit / supervised process). A
# supervised process inherits a minimal environment, and the differences are
# exactly what breaks package installation from the panel while it works over SSH:
#   - PATH may lack /usr/sbin:/sbin -> lsb_release / gpg not found.
#   - HOME may be unset or "/" -> `gpg --dearmor` cannot create its homedir, the
#     signing keyring is never written, the cloudflare repo stays unsigned, and
#     `apt install cloudflare-warp` then fails with "Unable to locate package".
#   - No TTY -> tput errors and apt may prompt.
# Pin all three so the install is deterministic regardless of how we were invoked.
export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"
export HOME="${HOME:-/root}"

# tput needs a known TERM; under the panel TERM is "dumb"/unset (no colors), so
# fall back to empty strings instead of letting tput error into the log.
tput_safe() { tput "$@" 2>/dev/null || true; }
GREEN=$(tput_safe setaf 2)
RED=$(tput_safe setaf 1)
BLUE=$(tput_safe setaf 4)
GOLD=$(tput_safe setaf 3)
CYAN=$(tput_safe setaf 6)
NC=$(tput_safe sgr0)

# warp-cli refuses the implicit Terms-of-Service prompt on EVERY registration/
# account command (registration new/delete, connect, status, …) when there is no
# TTY — and the panel always runs us non-interactively. So route every invocation
# through --accept-tos; it is harmless once the ToS has been accepted. This is why
# registration works over SSH (a TTY answers the prompt) but not from the panel.
wcli() { warp-cli --accept-tos "$@"; }

RPM_REPO_URL="https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo"
RPM_REPO_FILE="/etc/yum.repos.d/cloudflare-warp.repo"

root_check() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as ${RED}root!${NC}"
    exit 1
  fi
}

# Detect the package manager and dispatch to the matching installer.
# Order matters: check the most specific / official paths first.
check_host() {
    if command -v apt-get &> /dev/null; then
        apt_based
    elif command -v dnf &> /dev/null; then
        rpm_based dnf
    elif command -v microdnf &> /dev/null; then
        rpm_based microdnf
    elif command -v yum &> /dev/null; then
        rpm_based yum
    elif command -v zypper &> /dev/null; then
        zypper_based
    elif command -v pacman &> /dev/null; then
        pacman_based
    elif command -v rpm &> /dev/null; then
        echo "${RED}RPM-based system detected but no supported installer (dnf/microdnf/yum) found.${NC}"
        echo "Install 'dnf' or 'yum', then re-run this script."
        exit 1
    else
        echo "${RED}No supported package manager found (apt/dnf/yum/zypper/pacman).${NC}"
        exit 1
    fi
}

apt_based() {
    echo "${CYAN}Running apt-based installation...${NC}"
    # apt-get, not apt: apt has no stable CLI for scripts and misbehaves without a
    # TTY. install -d guarantees the keyrings dir; --batch --yes keeps gpg silent
    # and non-interactive so the dearmor works with the hardened HOME set above.
    apt-get update
    apt-get install -y curl gpg lsb-release apt-transport-https ca-certificates sudo
    install -d -m 0755 /usr/share/keyrings
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --batch --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
    apt-get update
    apt-get -y install cloudflare-warp
}

# Shared installer for RPM-based systems (dnf / microdnf / yum).
# Cloudflare ships a single .rpm repo that all three consume.
rpm_based() {
    local mgr="$1"
    echo "${CYAN}Running ${mgr}-based installation...${NC}"
    mkdir -p /etc/yum.repos.d

    # RHEL / CentOS / Rocky / AlmaLinux need EPEL for cloudflare-warp's
    # dependencies. Fedora does NOT (and must not enable it). Best-effort.
    local id=""
    [ -r /etc/os-release ] && id="$(. /etc/os-release; echo "$ID")"
    if [ "$id" != "fedora" ]; then
        echo "${CYAN}Enabling EPEL (required on RHEL-family)...${NC}"
        "$mgr" install -y epel-release 2> /dev/null || true
    fi

    curl -fsSl "$RPM_REPO_URL" | tee "$RPM_REPO_FILE" > /dev/null
    "$mgr" install -y curl || true
    "$mgr" install -y cloudflare-warp
}

# openSUSE / SUSE. Unofficial: Cloudflare provides no zypper repo,
# but the RPM repo works when added manually. Best-effort.
zypper_based() {
    echo "${CYAN}Running zypper-based installation (unofficial)...${NC}"
    zypper --non-interactive removerepo cloudflare-warp &> /dev/null
    zypper --non-interactive addrepo -f -G "$RPM_REPO_URL" cloudflare-warp
    zypper --non-interactive --gpg-auto-import-keys refresh
    zypper --non-interactive install cloudflare-warp
}

# Arch Linux. Cloudflare ships no official package; the community AUR
# package 'cloudflare-warp-bin' repackages the .deb. makepkg refuses to
# run as root, so build it via an AUR helper as the invoking user.
pacman_based() {
    echo "${CYAN}Running pacman-based installation (Arch / AUR)...${NC}"

    local builder="${SUDO_USER:-}"
    if [ -z "$builder" ] || [ "$builder" = "root" ]; then
        echo "${RED}Arch install needs a non-root user to build the AUR package.${NC}"
        echo "Re-run with sudo from a normal user account, e.g.:"
        echo "  ${GOLD}sudo bash warp-cli.sh${NC}"
        exit 1
    fi

    pacman -Sy --needed --noconfirm base-devel git sudo

    local helper=""
    if command -v yay &> /dev/null; then
        helper="yay"
    elif command -v paru &> /dev/null; then
        helper="paru"
    else
        echo "${RED}No AUR helper (yay/paru) found.${NC}"
        echo "Install one first, e.g. 'yay', then re-run this script."
        exit 1
    fi

    echo "${CYAN}Building cloudflare-warp-bin via ${helper} as user '${builder}'...${NC}"
    sudo -u "$builder" "$helper" -S --needed --noconfirm cloudflare-warp-bin

    echo "${CYAN}Enabling WARP service...${NC}"
    systemctl enable --now warp-svc &> /dev/null || true
}

warp_setup() {
    if ! command -v warp-cli &> /dev/null; then
        echo "${RED}WARP-CLI command not found after installation!${NC}"
        exit 1
    fi

    # Port comes from WARP_SOCKS_PORT when the panel runs us non-interactively;
    # only fall back to an interactive prompt when it is unset (manual SSH run).
    local port="${WARP_SOCKS_PORT:-}"
    if [ -z "$port" ]; then
        read -p "Enter SOCKS5 proxy port [${GOLD}10808${NC}]: " port
    fi
    port="${port:-10808}"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "${RED}Invalid port '${port}'. Falling back to 10808.${NC}"
        port=10808
    fi

    echo "${CYAN}Configuring WARP... (Waiting 2s for service to start)${NC}"
    sleep 2

    # A registration can survive a package reinstall (state lives in
    # /var/lib/cloudflare-warp, and warp-svc auto-registers on first start), and
    # `registration new` then refuses with "Old registration is still around". So
    # clear any existing one first — harmless when there is none.
    wcli registration delete > /dev/null 2>&1 || true

    if ! wcli registration new; then
        echo "${RED}Failed to register WARP client!${NC}"
        echo "This can happen if the service isn't ready. Try running 'warp-cli --accept-tos registration new' manually."
        exit 1
    fi

    if ! wcli mode proxy; then
        echo "${RED}Failed to set WARP mode to proxy.${NC}"
        exit 1
    fi

    if ! wcli proxy port "$port"; then
        echo "${RED}Failed to set WARP proxy port.${NC}"
        exit 1
    fi

    if ! wcli connect; then
        echo "${RED}Failed to connect to WARP!${NC}"
        exit 1
    fi

    echo ""
    echo "${CYAN}WARP is ready! ${GOLD}SOCKS5 port: ${port}${NC}"
    echo ""
}

apt_uninstall() {
    echo "Uninstalling for apt-based system..."
    apt-get purge -y cloudflare-warp
    rm -f /etc/apt/sources.list.d/cloudflare-client.list
    rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    apt-get update
}

rpm_uninstall() {
    local mgr="$1"
    echo "Uninstalling for ${mgr}-based system..."
    "$mgr" remove -y cloudflare-warp
    rm -f "$RPM_REPO_FILE"
}

zypper_uninstall() {
    echo "Uninstalling for zypper-based system..."
    zypper --non-interactive remove cloudflare-warp
    zypper --non-interactive removerepo cloudflare-warp &> /dev/null
}

pacman_uninstall() {
    echo "Uninstalling for pacman-based system..."
    pacman -Rns --noconfirm cloudflare-warp-bin
}

uninstall_warp() {
    echo "${RED}Uninstalling Cloudflare WARP...${NC}"


    if command -v warp-cli &> /dev/null; then
        echo "Disconnecting and unregistering..."
        wcli disconnect &> /dev/null
        wcli registration delete &> /dev/null
    fi


    if command -v systemctl &> /dev/null; then
        systemctl stop cloudflare-warp &> /dev/null
        systemctl disable cloudflare-warp &> /dev/null
        systemctl stop warp-svc.service &> /dev/null
        systemctl disable warp-svc.service &> /dev/null
    fi


    if command -v apt-get &> /dev/null; then
        apt_uninstall
    elif command -v dnf &> /dev/null; then
        rpm_uninstall dnf
    elif command -v microdnf &> /dev/null; then
        rpm_uninstall microdnf
    elif command -v yum &> /dev/null; then
        rpm_uninstall yum
    elif command -v zypper &> /dev/null; then
        zypper_uninstall
    elif command -v pacman &> /dev/null; then
        pacman_uninstall
    else
        echo "${RED}No supported package manager found. Cannot uninstall.${NC}"
        echo "Please remove 'cloudflare-warp' manually."
        exit 1
    fi

    echo "${GREEN}Cloudflare WARP uninstalled successfully.${NC}"
}

if [ "$1" == "uninstall" ] || [ "$1" == "--uninstall" ]; then
    root_check
    uninstall_warp
    exit 0
fi

if [ "$1" == "reinstall" ] || [ "$1" == "--reinstall" ]; then
    root_check
    echo "${GOLD}Reinstalling WARP...${NC}"
    uninstall_warp
    echo "${CYAN}--- Starting Installation ---${NC}"
    check_host
    warp_setup
    exit 0
fi

root_check

if command -v warp-cli &> /dev/null; then

    echo "${CYAN}WARP-CLI is already installed.${NC}"
    echo ""
    echo "What would you like to do?"
    echo "  (r) ${GOLD}Reinstall${NC} (uninstall, then install)"
    echo "  (u) ${RED}Uninstall${NC}"
    echo "  (q) ${GREEN}Quit${NC}"

    read -n 1 -p "Enter your choice [r/u/q]: " choice
    echo ""

    case "$choice" in
        r|R)
            echo "${GOLD}Reinstalling WARP...${NC}"
            uninstall_warp
            echo "${CYAN}--- Starting Installation ---${NC}"
            check_host
            warp_setup
            ;;
        u|U)
            uninstall_warp
            ;;
        q|Q|*)
            echo "Aborting."
            exit 0
            ;;
    esac
else
    echo "${GREEN}WARP-CLI not found. Starting installation...${NC}"
    check_host
    warp_setup
fi

exit 0
