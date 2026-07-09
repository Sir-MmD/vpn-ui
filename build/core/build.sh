#!/usr/bin/env bash
#
# build/core/build.sh — Build the pinned Xray core + fetch the base geo files
# that get embedded into the panel binary (go:embed) and extracted at runtime by
# the `corebundle` package.
#
# The panel ships a SPECIFIC patched Xray-core fork (Sir-MmD/Xray-core) whose
# Shadowsocks per-user `method` fallback the product depends on. This script
# produces that exact core, statically linked (CGO_ENABLED=0) so it runs on any
# Linux distro, and drops it — plus geoip.dat/geosite.dat — where the go:embed
# picks them up.
#
# Output layout (consumed by corebundle's //go:embed all:core):
#   corebundle/core/<goarch>/xray
#   corebundle/core/geoip.dat
#   corebundle/core/geosite.dat
#
# Usage:
#   build/core/build.sh [goarch...]        # default: amd64
#
# Source of truth is the pinned submodule third_party/Xray-core (@ a fixed
# commit). It's used automatically when present; the clone path below is only a
# fallback for checkouts where the submodule wasn't initialised.
#
# Env:
#   XRAY_SRC   path to a local Xray-core checkout (overrides the submodule)
#   XRAY_REPO  fork git URL for the fallback clone (default: Sir-MmD/Xray-core)
#   XRAY_REF   git ref for the fallback clone       (default: default branch)
#   GEO_ONLY=1 only refresh geo files, skip the core build
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_ROOT="$REPO_ROOT/corebundle/core"

# shellcheck source=../lib/log.sh
source "$REPO_ROOT/build/lib/log.sh" 2>/dev/null || { step(){ echo "==> $*"; }; ok(){ echo "  - $*"; }; info(){ echo "  $*"; }; warn(){ echo "  ! $*" >&2; }; err(){ echo "  x $*" >&2; }; hr(){ :; }; }

XRAY_REPO="${XRAY_REPO:-https://github.com/Sir-MmD/Xray-core}"
XRAY_REF="${XRAY_REF:-}"
ARCHES=("${@:-amd64}")

mkdir -p "$OUT_ROOT"

# --- base geo files (architecture-independent) ---------------------------------
# Same source the dashboard's "Update geofiles" uses (Loyalsoldier/v2ray-rules-dat),
# so the bundled fallback matches what a later dashboard update would fetch.
# Download one geo file ONLY when it changed. `-z <cached>` sends a conditional
# request (If-Modified-Since the cached file's mtime); the server answers 304 and
# no body when it's current, so we keep the cache and skip the ~14MB transfer. A
# fetch failure keeps the existing copy (geo is a runtime-updatable fallback).
# GEO_FORCE=1 always re-downloads.
_geo_one() {
    local url="$1" out="$2" tmp rc=0
    if [[ "${GEO_FORCE:-0}" != "1" && -s "$out" ]]; then
        tmp="$(mktemp)"
        curl -fsSL --retry 3 -z "$out" -o "$tmp" "$url" || rc=$?
        if [[ $rc -eq 0 && -s "$tmp" ]]; then
            mv "$tmp" "$out"; ok "$(basename "$out"): updated"
        elif [[ $rc -eq 0 ]]; then
            rm -f "$tmp"; info "$(basename "$out"): up to date (304) — skipped"
        else
            rm -f "$tmp"; warn "$(basename "$out"): check failed (rc=$rc) — keeping cached copy"
        fi
    else
        curl -fL --retry 3 -o "$out" "$url"; ok "$(basename "$out"): fetched"
    fi
}

fetch_geo() {
    local base="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
    step "Checking base geo files (conditional; GEO_FORCE=1 to force a refresh)"
    _geo_one "$base/geoip.dat"   "$OUT_ROOT/geoip.dat"
    _geo_one "$base/geosite.dat" "$OUT_ROOT/geosite.dat"
    info "geo: $(ls -lh "$OUT_ROOT"/geoip.dat "$OUT_ROOT"/geosite.dat | awk '{print $5, $9}' | tr '\n' ' ')"
}

# --- the pinned core -----------------------------------------------------------
prepare_src() {
    if [[ -n "${XRAY_SRC:-}" ]]; then
        echo "$XRAY_SRC"
        return
    fi
    # Prefer the pinned submodule checkout (third_party/Xray-core @ <sha>) — this
    # is the reproducible source of truth. Bump it with a normal submodule update.
    if [[ -f "$REPO_ROOT/third_party/Xray-core/go.mod" ]]; then
        echo "$REPO_ROOT/third_party/Xray-core"
        return
    fi
    # Fallback: submodule not initialised. Clone into a PERSISTENT cache (default
    # outside the repo so it survives fresh checkouts too) so we clone ONCE, then
    # only `git fetch` to pick up updates on later runs — never re-clone every
    # build. Override the location with XRAY_CACHE.
    local cache="${XRAY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/vpn-ui-build/Xray-core}"
    if [[ -d "$cache/.git" ]]; then
        info "reusing cached Xray-core clone ($cache); fetching updates" >&2
        git -C "$cache" remote set-url origin "$XRAY_REPO" >/dev/null 2>&1 || true
        if [[ -n "$XRAY_REF" ]]; then
            git -C "$cache" fetch --depth 1 origin "$XRAY_REF" >&2 2>&1 &&
                git -C "$cache" checkout -q FETCH_HEAD >&2 2>&1 || true
        else
            git -C "$cache" fetch --depth 1 origin >&2 2>&1 &&
                git -C "$cache" checkout -q FETCH_HEAD >&2 2>&1 || true
        fi
    else
        mkdir -p "$(dirname "$cache")"
        step "cloning Xray-core into cache $cache (first time only)" >&2
        if [[ -n "$XRAY_REF" ]]; then
            git clone --depth 1 --branch "$XRAY_REF" "$XRAY_REPO" "$cache" >&2
        else
            git clone --depth 1 "$XRAY_REPO" "$cache" >&2
        fi
    fi
    echo "$cache"
}

build_core() {
    local src
    src="$(prepare_src)"
    # The commit the source is at. If the cached xray was built from this same
    # commit, there is nothing to rebuild — skip the (slow) go build. Bump the
    # submodule/ref to trigger a rebuild, or set CORE_FORCE=1.
    local srccommit
    srccommit="$(git -C "$src" rev-parse HEAD 2>/dev/null || echo unknown)"
    info "pinned Xray core source: $src @ ${srccommit:0:12}"
    for goarch in "${ARCHES[@]}"; do
        local outdir="$OUT_ROOT/$goarch"
        mkdir -p "$outdir"
        local marker="$outdir/.xray.commit"
        if [[ "${CORE_FORCE:-0}" != "1" && -x "$outdir/xray" && "$srccommit" != "unknown" \
              && "$(cat "$marker" 2>/dev/null)" == "$srccommit" ]]; then
            ok "core ($goarch) already built from ${srccommit:0:12} — skipping (CORE_FORCE=1 to rebuild)"
            continue
        fi
        step "go build xray ($goarch, CGO_ENABLED=0, static)"
        ( cd "$src" && \
          CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
          go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -v -o "$outdir/xray" ./main )
        chmod 0755 "$outdir/xray"
        echo "$srccommit" > "$marker"
        file "$outdir/xray" || true
        ok "core: $(ls -lh "$outdir/xray" | awk '{print $5, $9}')"
    done
}

fetch_geo
if [[ "${GEO_ONLY:-0}" != "1" ]]; then
    build_core
fi
step "Done. Embed contents:"
ls -lhR "$OUT_ROOT"
