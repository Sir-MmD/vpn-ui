#!/usr/bin/env bash
# vpn-ui test unit — root entrypoint.
# Usage: sudo ./run.sh [--only ubuntu-24,arch] [--concurrency N] [-c config.toml]
# On start it auto-checks the backend (incus + python) and installs/inits
# anything missing via setup.sh, sets host net prerequisites (IPv4 forwarding),
# and sweeps leftover harness VMs/bridges from a prior aborted/unchecked run
# (also on error/Ctrl-C) before running.
set -euo pipefail

# ======================= TEST CONFIG (edit here) =======================
# Distros to test. Comment out / delete lines to skip. Names must match the
# server names in config.toml. Leave the array EMPTY to test all of them.
DISTROS=(
#  ubuntu-22
  ubuntu-24
  ubuntu-26
  debian-12
  debian-13
#  fedora-42   # image removed from images: remote (F42 EOL)
  fedora-43
  fedora-44
#  alma-8
  alma-9
  alma-10
#  rocky-8
  rocky-9
  rocky-10
  arch
)

# How many distros to test in parallel. Each = 1 server + 2 client VMs, on its
# own isolated bridge. Watch host RAM/disk: N jobs ≈ N×3 VMs at once.
# EMPTY = use the `concurrency:` value from config.toml (the default). Put a
# number here (or pass --concurrency N) only to override config.toml.
CONCURRENCY=""
# =======================================================================
# CLI flags (--only / --concurrency) passed to this script override the above.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

# --- help (works without root; must precede the root check) ---
for arg in "$@"; do
  case "$arg" in
    -h|--help)
      cat <<'EOF'
vpn-ui test unit — parallel incus E2E matrix over server distros.

Usage: sudo ./run.sh [--only d1,d2] [--concurrency N] [--tests t1,t2] [-c config.toml]

Flags:
  --only d1,d2       only run these distros (names from config.toml / DISTROS)
  --concurrency N    run N distros in parallel (overrides config.toml)
  --tests t1,t2      only run these tests (comma-separated; default: all)
  -c, --config FILE  config file (default: test_unit/config.toml)
  -h, --help         show this help and exit

Tests (ids mirror harness/model.py:ALL_PHASES; always run in this fixed order):
  core-init       provision kernel modules + packages + xray core
  server-setup    create inbounds + accounts + source-IP routing rules
  openvpn         connect variants + checks + peer reachability (OpenVPN)
  l2tp            connect variants + checks + peer reachability (L2TP/IPsec)
  pptp            connect variants + checks + peer reachability (PPTP)
  bulk-ops        bulk client add/sub/enable/disable + TXT/PDF export via API
  backup-restore  DB export + import round-trip
  warp-socks      Cloudflare warp-cli SOCKS install + egress
  random-cfg      --random switch: randomize port + creds + webpath, then restore
  systemd         --systemd switch: install + run the panel as a systemd unit
  uninstall       --uninstall switch: install everything, tear down, assert clean host
  export-js       host-side Node TXT/PDF export test (no VM)

Notes:
  * Substrate phases core-init and server-setup ALWAYS run (plus client-prep);
    --tests only filters the optional phases above.
  * Phases always run in the fixed order shown, regardless of --tests order.
  * "all" (or an empty --tests) selects every test.

Example:
  sudo ./run.sh --only arch --tests openvpn,uninstall
EOF
      exit 0
      ;;
  esac
done

# --- must be root (incus VM launch, kernel-module provisioning) ---
if [[ "${EUID}" -ne 0 ]]; then
  echo "FATAL: must run as root (incus + provisioning need it)." >&2
  exit 1
fi

# NOTE: NO polkit prompt here. The harness opens each test bridge in whatever
# host firewall is active — firewalld (trusted zone) or ufw (route allow),
# no-op for plain nftables/iptables which incus manages itself. firewall-cmd
# runs with the desktop agent stripped, so there is NO KDE/GNOME password
# dialog. See harness/incus.py::firewall_open_bridge.

# --- backend bootstrap (incus + python + incus init), cross-distro ---
# setup.sh is idempotent and covers apt/dnf/yum/pacman. It runs automatically
# whenever the backend isn't ready, and installs whatever is missing; on an
# already-provisioned host it's a no-op, so a normal run pays no cost.
backend_ready() {
  command -v incus   >/dev/null 2>&1 || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  incus info         >/dev/null 2>&1 || return 1
  # a bare `incus info` passes even with no storage pool; the harness needs one
  incus storage list --format csv 2>/dev/null | grep -q . || return 1
}

if ! backend_ready; then
  echo "[run] backend not ready — running setup.sh to install/init it..." >&2
  bash "$SCRIPT_DIR/setup.sh"
  backend_ready \
    || { echo "FATAL: backend still not ready after setup.sh (see log above)." >&2; exit 1; }
fi

# --- binary must sit in the test_subject/ folder (with its bin/ dir) ---
if [[ ! -f "$SCRIPT_DIR/test_subject/vpn-ui" ]]; then
  echo "FATAL: '$SCRIPT_DIR/test_subject/vpn-ui' not found. Place the prebuilt vpn-ui binary (and its bin/ dir) in test_subject/." >&2
  exit 1
fi

# --- python deps (requests; TOML config is read with the stdlib tomllib) ---
if ! python3 -c 'import requests' >/dev/null 2>&1; then
  echo "[setup] installing python deps..."
  pip3 install -q -r "$SCRIPT_DIR/requirements.txt" \
    || python3 -m pip install -q --break-system-packages -r "$SCRIPT_DIR/requirements.txt"
fi

# --- assemble args from the TEST CONFIG block (CLI "$@" overrides) ---
# Only pass --concurrency when the block above sets one; empty => config.toml wins.
ARGS=()
if [[ -n "$CONCURRENCY" ]]; then
  ARGS+=(--concurrency "$CONCURRENCY")
fi
if [[ ${#DISTROS[@]} -gt 0 ]]; then
  only="$(IFS=,; echo "${DISTROS[*]}")"
  ARGS+=(--only "$only")
fi

# --- pull the --tests value out of "$@" (it still flows through to argparse) ---
# so the host-side export.js gate below can honor it. Accept both `--tests x,y`
# and `--tests=x,y`.
TESTS_SEL=""
_prev=""
for arg in "$@"; do
  case "$arg" in
    --tests=*) TESTS_SEL="${arg#*=}" ;;
    --tests)   _prev="tests" ;;
    *)         [[ "$_prev" == "tests" ]] && TESTS_SEL="$arg"; _prev="" ;;
  esac
done

# --- export.js TXT/PDF test (host-side, browserless) ---
# The account TXT/PDF export is pure client-side JS (jsPDF/QRious). This runs the
# real export.js under Node with stubbed browser globals and asserts the TXT/PDF
# output + that a QR is embedded only for xray share-links. Distro-independent, so
# it runs once here as a pre-flight rather than per VM.
# Gated by --tests: runs when unset/empty, or when it contains export-js / all.
if [[ -z "$TESTS_SEL" || ",$TESTS_SEL," == *",export-js,"* || ",$TESTS_SEL," == *",all,"* ]]; then
  if command -v node >/dev/null 2>&1; then
    echo "[run] export.js TXT/PDF test..."
    if ! node "$SCRIPT_DIR/export_test/export.test.js"; then
      echo "FATAL: export.js TXT/PDF test failed (see output above)." >&2
      exit 1
    fi
  else
    echo "[run] node not found — skipping export.js TXT/PDF test (install node to enable)." >&2
  fi
else
  echo "[run] export-js not selected — skipping"
fi

# --- environment + leftover cleanup ------------------------------------------
# Harness resources are deterministically named: instances `vpnt<i>-{srv,cla,clb,clc}`
# and bridges `vt<i>` (i = job index). A crashed / Ctrl-C'd run — or one that used
# higher concurrency, or distros since unchecked — can leave some behind and block
# the next run with "already exists". sweep() force-removes ALL of them (any index)
# and drops any per-bridge firewall opening. Idempotent + best-effort. Assumes a
# single matrix at a time (don't run two ./run.sh concurrently on one host).
sweep() {
  command -v incus >/dev/null 2>&1 || return 0
  local n found=""
  for n in $(incus list --format csv -c n 2>/dev/null | grep -E '^vpnt[0-9]+-' || true); do
    incus delete "$n" --force >/dev/null 2>&1 || true; found=1
  done
  for n in $(incus network list --format csv 2>/dev/null | cut -d, -f1 | grep -E '^vt[0-9]+$' || true); do
    command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --zone=trusted --remove-interface="$n" >/dev/null 2>&1 || true
    if command -v ufw >/dev/null 2>&1; then
      ufw route delete allow in on "$n"  >/dev/null 2>&1 || true
      ufw route delete allow out on "$n" >/dev/null 2>&1 || true
      ufw delete allow in on "$n"        >/dev/null 2>&1 || true
    fi
    incus network delete "$n" >/dev/null 2>&1 || true; found=1
  done
  [[ -n "$found" ]] && echo "[run] swept leftover harness VMs/networks" >&2 || true
}

# Host network prerequisite for the managed bridges: IPv4 forwarding must be on or
# the VMs get no NAT'd internet (incus installs the per-bridge nft rules itself).
net_env_setup() {
  [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" == "1" ]] \
    || sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
}

# Safety net: on error or Ctrl-C, sweep leftovers (the orchestrator cleans up per
# job on a normal run, so on success this is a no-op). Runs only on non-zero exit.
_on_exit() {
  local rc=$?
  [[ "$rc" -ne 0 ]] && { echo "[run] exit rc=$rc — sweeping leftover VMs/networks..." >&2; sweep; }
}
trap _on_exit EXIT

net_env_setup
sweep   # clear leftovers from any prior aborted/unchecked run before starting

# --- run (module path rooted at test_unit's parent) ---
# NOT exec: keep this shell alive so the EXIT trap fires on error/interrupt.
cd "$PARENT_DIR"
python3 -m test_unit.harness.orchestrator "${ARGS[@]}" "$@"
