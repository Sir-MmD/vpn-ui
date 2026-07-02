#!/usr/bin/env bash
#
# build/backend/build.sh — Build portable, statically-linked VPN daemon binaries
# that get embedded into the x-ui binary (go:embed) and extracted at runtime.
#
# The daemons are built against musl (Alpine) and statically linked, so the
# resulting binaries run on any Linux distro/glibc version without depending on
# the host's package manager. This is what lets the panel "bake in" the backend
# instead of installing xl2tpd/libreswan/openvpn per-distro.
#
# Output layout (consumed by the `backend` Go package's //go:embed):
#   backend/bin/<goarch>/<daemon>
#
# Usage:
#   build/backend/build.sh [goarch...]     # default: amd64
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_ROOT="$REPO_ROOT/backend/bin"

# goarch -> Alpine build platform (docker --platform)
declare -A PLATFORM=(
    [amd64]="linux/amd64"
    [arm64]="linux/arm64"
)

ARCHES=("${@:-amd64}")

build_arch() {
    local goarch="$1"
    local platform="${PLATFORM[$goarch]:-}"
    if [[ -z "$platform" ]]; then
        # Not an error: the Go embed simply has no bundle for this arch, so the
        # daemons fall back to the host package manager there. Keeps CI green for
        # arches we don't (yet) build daemons for (armv7, s390x, …).
        echo "==> No daemon bundle for '$goarch' (unsupported) — skipping" >&2
        return 0
    fi
    local outdir="$OUT_ROOT/$goarch"
    mkdir -p "$outdir"

    echo "==> Building daemons for $goarch ($platform)"
    # DOCKER_NET lets the caller pick host networking when the default bridge is
    # firewalled (common with firewalld on the build host).
    docker run --rm ${DOCKER_NET:-} --platform "$platform" -v "$outdir:/out" alpine:3.20 sh -euxc '
        apk add --no-cache build-base linux-headers pkgconf git wget file \
            openssl-dev openssl-libs-static libcap-ng-dev libcap-ng-static

        # --- xl2tpd (static) ---
        git clone --depth 1 https://github.com/xelerance/xl2tpd /src/xl2tpd
        cd /src/xl2tpd
        # Only the main daemon + control tool are needed (pfc requires libpcap).
        make -j"$(nproc)" xl2tpd xl2tpd-control LDFLAGS="-static"
        cp xl2tpd xl2tpd-control /out/
        strip /out/xl2tpd /out/xl2tpd-control || true

        # --- openvpn (static) ---
        cd /tmp
        OVPN_VER=2.6.12
        wget -q "https://swupdate.openvpn.org/community/releases/openvpn-${OVPN_VER}.tar.gz"
        tar xf "openvpn-${OVPN_VER}.tar.gz"
        cd "openvpn-${OVPN_VER}"
        # Minimal build (no lzo/lz4/plugins/dco); keep management (panel uses the
        # mgmt socket). Force static archives for the deps configure would take
        # dynamically. libtool strips a plain -static, so pass -all-static at make.
        ./configure --disable-lzo --disable-lz4 --disable-plugins --disable-dco --disable-unit-tests \
            OPENSSL_LIBS="-l:libssl.a -l:libcrypto.a" \
            LIBCAPNG_CFLAGS=" " LIBCAPNG_LIBS="-l:libcap-ng.a"
        make -j"$(nproc)" LDFLAGS="-all-static -s"
        cp src/openvpn/openvpn /out/openvpn

        # --- pptpd (static) ---
        # pptpd execs pptpctrl at the compile-time SBINDIR path (no PATH lookup),
        # so pin it to a fixed sentinel that provisioning symlinks to the bundle.
        cd /tmp
        wget -q "https://downloads.sourceforge.net/project/poptop/pptpd/pptpd-1.4.0/pptpd-1.4.0.tar.gz" -O pptpd.tar.gz
        tar xf pptpd.tar.gz
        cd pptpd-1.4.0
        ./configure --sbindir=/usr/libexec/vpn-ui
        make pptpd pptpctrl LDFLAGS="-static"
        cp pptpd pptpctrl /out/
        strip /out/pptpd /out/pptpctrl || true

        # Confirm all outputs are static
        for b in /out/xl2tpd /out/xl2tpd-control /out/openvpn /out/pptpd /out/pptpctrl; do
            if ! file "$b" | grep -q "statically linked"; then
                echo "WARNING: $b is not statically linked" >&2
            fi
        done
    '
    echo "==> Done: $(ls -lh "$outdir")"
}

for a in "${ARCHES[@]}"; do
    build_arch "$a"
done
