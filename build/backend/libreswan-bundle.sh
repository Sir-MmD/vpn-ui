#!/bin/sh
#
# build/backend/libreswan-bundle.sh — assemble the relocatable ALL_ALGS libreswan
# (IPsec) bundle.
#
# Runs INSIDE an Alpine (musl) container. We build libreswan FROM SOURCE with
# USE_DH2=true so the resulting pluto offers the MODP1024 (DH group 2) group that
# Windows 7 / legacy L2TP-IPsec clients need — distro packages ship USE_DH2=false
# and there is no runtime switch for it.
#
# pluto can't be a single static binary: it links NSS (which itself dlopens
# libsoftokn3/libfreebl3 at runtime), NSPR, libevent and gmp. So — exactly like
# the pppd bundle — we copy pluto + its helper programs + the `ipsec` wrapper +
# every shared-lib dependency + the NSS PKCS#11 modules + the musl loader into a
# tree rooted at a FIXED path (backend.LibreswanBundleRoot), and drive each ELF
# through per-program launcher wrappers that invoke the bundled musl loader with
# --library-path. That makes the whole thing run on ANY host libc (glibc too).
#
# The tree is tarred to /out/libreswan-bundle.tgz, consumed by backend/libreswan.go.
# The fixed paths here MUST match backend/libreswan.go's constants.
#
#   PREFIX_IN_TREE  = /usr/libexec/vpn-ui/libreswan   (== LibreswanBundleRoot)
#     sbin/ipsec    launcher for the `ipsec` wrapper (sets IPSEC_* + loader)
#     sbin/pluto    launcher for the pluto daemon (procmgr runs this directly)
#     libexec/ipsec/<prog>      per-program loader wrappers
#     libexec/ipsec/<prog>.bin  the real ELF (or .sh for script helpers)
#     lib/          .so deps + NSS modules + musl loader
#
# NOTE: musl-relocating a daemon this complex is iterative — expect to run this a
# couple of times on a real Docker host and adjust. The build FAILS LOUDLY if the
# finished tree's pluto does not actually report MODP1024, so a green build means
# the ALL_ALGS goal was met.
set -eu

PREFIX=/usr/libexec/vpn-ui/libreswan     # must equal backend.LibreswanBundleRoot
# pluto has IPSEC_EXECDIR compiled in and execs addconn/_updown from it directly
# (ignoring env), so it MUST be the bundle's real libexec path — otherwise pluto
# looks for addconn under the distro default /usr/libexec/ipsec and dies.
EXECDIR="$PREFIX/libexec/ipsec"
ARCH="${ARCH:-x86_64}"                    # musl loader arch (amd64 => x86_64)
LOADER="ld-musl-${ARCH}.so.1"
LIBRESWAN_VER="${LIBRESWAN_VER:-4.15}"    # pinned; 4.15 is a widely-packaged, musl-friendly stable
ROOT=/tmp/lswanroot
# Assemble the tree at its REAL deploy path inside the (disposable) build
# container, not under a staging root — the launcher wrappers hard-code $PREFIX,
# so the build-time self-check (pluto --selftest via the wrappers) only resolves
# when the tree actually lives there. Safe: this always runs inside Alpine/Docker.
DEST="$PREFIX"

echo "== building libreswan $LIBRESWAN_VER (USE_DH2=true) on Alpine musl =="

# Build + runtime deps. NSS/NSPR = crypto, libevent = event loop, gmp = bignum,
# libcap-ng = capability drop, flex/bison = the ipsec.conf parser generators.
# bsd-compat-headers supplies <sys/queue.h>/<sys/cdefs.h>/<sys/tree.h>, which musl
# omits but libreswan's confread.h (TAILQ_*) needs — the same fix Alpine's own
# libreswan aport uses.
# nss-tools provides certutil/pk12util — libreswan's `ipsec checknss`/`initnss`
# shell out to them to create the NSS database, so they get bundled too.
apk add --no-cache \
    build-base linux-headers pkgconf git wget file bash bsd-compat-headers \
    nss-dev nspr-dev libevent-dev gmp-dev libcap-ng-dev flex bison \
    nss nss-tools nspr libevent gmp libcap-ng >/dev/null

# --- fetch source -------------------------------------------------------------
cd /tmp
wget -q "https://download.libreswan.org/libreswan-${LIBRESWAN_VER}.tar.gz"
tar xf "libreswan-${LIBRESWAN_VER}.tar.gz"
cd "libreswan-${LIBRESWAN_VER}"

# --- compile ------------------------------------------------------------------
# USE_DH2=true is the whole point. Everything else is trimmed to shrink the
# dependency closure we have to relocate: no DNSSEC (unbound/ldns), no systemd,
# no audit/seccomp/labeled-ipsec/LDAP/NM. USE_XFRM stays on — it's the Linux
# kernel data-plane libreswan drives. -Wno-error keeps musl's stricter warnings
# from failing the build.
MAKE_VARS="
    USE_DH2=true
    USE_DNSSEC=false
    USE_LIBCURL=false
    USE_AUTHPAM=false
    USE_SYSTEMD_WATCHDOG=false
    USE_LINUX_AUDIT=false
    USE_SECCOMP=false
    USE_LABELED_IPSEC=false
    USE_NM=false
    USE_LDAP=false
    USE_XFRM=true
    INITSYSTEM=sysvinit
    PREFIX=/usr
    FINALLIBEXECDIR=$EXECDIR
    WERROR_CFLAGS=-Wno-error
"
# STAGE is overridable so an already-compiled tree can be reused (fast iteration
# on the relocatable-tree assembly without a ~3-minute recompile).
STAGE="${STAGE:-$ROOT/staging}"
if [ ! -x "$STAGE$EXECDIR/pluto" ]; then
    make $MAKE_VARS -j"$(nproc)" base
    make $MAKE_VARS DESTDIR="$STAGE" install-base
fi

REAL_EXECDIR="$STAGE$EXECDIR"
REAL_IPSEC="$STAGE/usr/sbin/ipsec"
[ -x "$REAL_EXECDIR/pluto" ] || { echo "!! pluto not built at $REAL_EXECDIR/pluto" >&2; exit 1; }

# --- assemble relocatable tree ------------------------------------------------
rm -rf "$DEST"
mkdir -p "$DEST/sbin" "$DEST/lib" "$DEST/libexec/ipsec"

# The musl loader (a real file; libc.musl-* is a symlink to it).
cp "/lib/$LOADER" "$DEST/lib/$LOADER"
ln -sf "$LOADER" "$DEST/lib/libc.musl-${ARCH}.so.1"

# Copy every program libreswan installed under libexec/ipsec. ELF programs become
# <name>.bin + a loader wrapper <name>; shell/python helpers are copied as-is.
for prog in "$REAL_EXECDIR"/*; do
    name="$(basename "$prog")"
    if file "$prog" | grep -q 'ELF'; then
        cp "$prog" "$DEST/libexec/ipsec/$name.bin"
        cat > "$DEST/libexec/ipsec/$name" <<EOF
#!/bin/sh
B=$PREFIX
export LD_LIBRARY_PATH="\$B/lib:\${LD_LIBRARY_PATH:-}"
exec "\$B/lib/$LOADER" --library-path "\$B/lib" "\$B/libexec/ipsec/$name.bin" "\$@"
EOF
        chmod 0755 "$DEST/libexec/ipsec/$name"
    else
        cp "$prog" "$DEST/libexec/ipsec/$name"
        chmod 0755 "$DEST/libexec/ipsec/$name" || true
    fi
done

# NSS command-line tools. `ipsec checknss`/`initnss` shell out to certutil (and
# pk12util) to create the NSS database, and they are looked up on PATH — so bundle
# them next to the other programs and put that dir on the wrappers' PATH below, so
# NSS init works on a host that has no nss-tools of its own.
for tool in certutil pk12util; do
    tbin="$(command -v "$tool" || true)"
    [ -n "$tbin" ] || continue
    cp "$tbin" "$DEST/libexec/ipsec/$tool.bin"
    cat > "$DEST/libexec/ipsec/$tool" <<EOF
#!/bin/sh
B=$PREFIX
export LD_LIBRARY_PATH="\$B/lib:\${LD_LIBRARY_PATH:-}"
exec "\$B/lib/$LOADER" --library-path "\$B/lib" "\$B/libexec/ipsec/$tool.bin" "\$@"
EOF
    chmod 0755 "$DEST/libexec/ipsec/$tool"
done

# The `ipsec` command wrapper (a script). Copy it, then front it with a launcher
# that pins every IPSEC_* directory into the bundle so its subcommand lookups hit
# our per-program wrappers, not the host.
cp "$REAL_IPSEC" "$DEST/libexec/ipsec/ipsec.real"
chmod 0755 "$DEST/libexec/ipsec/ipsec.real"
cat > "$DEST/sbin/ipsec" <<EOF
#!/bin/sh
# vpn-ui bundled libreswan 'ipsec' launcher — generated by libreswan-bundle.sh.
B=$PREFIX
export IPSEC_EXECDIR="\$B/libexec/ipsec"
export IPSEC_LIBEXECDIR="\$B/libexec/ipsec"
export IPSEC_SBINDIR="\$B/sbin"
export IPSEC_NSSDIR="\${IPSEC_NSSDIR:-/etc/ipsec.d}"
export IPSEC_CONFS="\${IPSEC_CONFS:-/etc}"
export LD_LIBRARY_PATH="\$B/lib:\${LD_LIBRARY_PATH:-}"
# so checknss/initnss find the bundled certutil/pk12util (and our subcommands).
export PATH="\$B/libexec/ipsec:\$B/sbin:\$PATH"
exec "\$B/libexec/ipsec/ipsec.real" "\$@"
EOF
chmod 0755 "$DEST/sbin/ipsec"

# Direct pluto launcher — procmgr runs this as a child process. --nssdir/--secretsfile
# and --config are supplied by the caller; here we only fix the loader + IPSEC_* env.
cat > "$DEST/sbin/pluto" <<EOF
#!/bin/sh
# vpn-ui bundled pluto launcher — generated by libreswan-bundle.sh.
B=$PREFIX
export IPSEC_EXECDIR="\$B/libexec/ipsec"
export IPSEC_LIBEXECDIR="\$B/libexec/ipsec"
export LD_LIBRARY_PATH="\$B/lib:\${LD_LIBRARY_PATH:-}"
exec "\$B/lib/$LOADER" --library-path "\$B/lib" "\$B/libexec/ipsec/pluto.bin" "\$@"
EOF
chmod 0755 "$DEST/sbin/pluto"

# --- collect shared-lib deps + NSS runtime modules ----------------------------
# NSS dlopens these PKCS#11 modules at runtime — ldd will NOT list them, so copy
# them explicitly (mirrors how the pppd bundle copies OpenSSL's legacy.so).
# libfreeblpriv3.so is the ONE that matters: Alpine's libfreebl3.so is a tiny stub
# and softoken dlopens libfreeblpriv3.so for the actual crypto — without it NSS
# init dies with CKR_DEVICE_ERROR. Copy the whole softoken/freebl module set.
NSS_LIBDIR="$(dirname "$(find /usr/lib /lib -name 'libsoftokn3.so' 2>/dev/null | head -1)")"
for m in libsoftokn3.so libfreebl3.so libfreeblpriv3.so libnssckbi.so libnssdbm3.so; do
    [ -f "$NSS_LIBDIR/$m" ] && cp -L "$NSS_LIBDIR/$m" "$DEST/lib/$m" || true
done

# Recursively copy every NEEDED shared lib into the bundle's lib/ so nothing
# resolves to a host path.
collect() {
    for f in "$@"; do
        [ -f "$f" ] || continue
        ldd "$f" 2>/dev/null | awk '/=>/ {print $3}' | while read -r lib; do
            [ -f "$lib" ] || continue
            base=$(basename "$lib")
            [ -e "$DEST/lib/$base" ] && continue
            cp -L "$lib" "$DEST/lib/$base"
        done
    done
}
collect "$DEST"/libexec/ipsec/*.bin "$DEST"/lib/*.so*
collect "$DEST"/lib/*.so*          # deps-of-deps (libssl3 -> libnspr4, etc.)

# --- self-check: the finished tree MUST expose MODP1024 (DH2), else the build is
# moot. pluto --selftest initializes NSS first, so give it a throwaway NSS db —
# without one it aborts with SEC_ERROR_BAD_DATABASE before ever listing DH groups.
echo "== verifying bundled pluto reports MODP1024 (DH2, IKEv1) =="
TESTNSS="$(mktemp -d)"
"$DEST/libexec/ipsec/certutil" -N -d "sql:$TESTNSS" --empty-password
if "$DEST/sbin/ipsec" pluto --selftest --nssdir "$TESTNSS" 2>&1 | grep -qi 'MODP1024'; then
    echo "== OK: MODP1024 present in bundled pluto =="
else
    echo "!! bundled pluto --selftest does NOT list MODP1024 — USE_DH2 build failed" >&2
    "$DEST/sbin/ipsec" pluto --selftest --nssdir "$TESTNSS" 2>&1 | tail -25 >&2
    exit 1
fi
rm -rf "$TESTNSS"

# --- package ------------------------------------------------------------------
# Tar the tree at its real path so ExtractLibreswanBundle (untar to /) recreates
# /usr/libexec/vpn-ui/libreswan exactly.
mkdir -p /out
tar czf /out/libreswan-bundle.tgz -C / "${PREFIX#/}"
echo "== libreswan-bundle.tgz built (libreswan $LIBRESWAN_VER, USE_DH2=true) =="
ls -lh /out/libreswan-bundle.tgz | awk '{print "== size: "$5}'
