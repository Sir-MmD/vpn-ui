#!/usr/bin/env bash
#
# build/lib/log.sh — shared colored logging for the vpn-ui build scripts.
# Sourced by build.sh + build/*/build.sh. Colors auto-disable when stdout is not
# a TTY or when NO_COLOR is set (https://no-color.org), so piped/CI logs stay clean.
#
# Helpers (all but warn/err print to stdout):
#   step  MSG   bold cyan "==>" section banner
#   ok    MSG   green "✓" success / cached / skipped-fine
#   info  MSG   dim secondary detail
#   warn  MSG   yellow "!"  (stderr)
#   err   MSG   red   "✗"  (stderr)
#   hr          faint horizontal rule
# Colors on when stdout is a TTY (or FORCE_COLOR is set), and NO_COLOR is unset.
# shellcheck disable=SC2034
if [[ ( -t 1 || -n "${FORCE_COLOR:-}" ) && -z "${NO_COLOR:-}" ]]; then
    _CR=$'\033[0m'; _CB=$'\033[1m'; _CD=$'\033[2m'
    _Cr=$'\033[31m'; _Cg=$'\033[32m'; _Cy=$'\033[33m'
    _Cb=$'\033[34m'; _Cc=$'\033[36m'; _Cm=$'\033[35m'
else
    _CR=''; _CB=''; _CD=''; _Cr=''; _Cg=''; _Cy=''; _Cb=''; _Cc=''; _Cm=''
fi

step() { printf '%s\n' "${_CB}${_Cc}==>${_CR} ${_CB}$*${_CR}"; }
ok()   { printf '%s\n' "  ${_Cg}✓${_CR} $*"; }
info() { printf '%s\n' "  ${_CD}$*${_CR}"; }
warn() { printf '%s\n' "  ${_Cy}!${_CR} $*" >&2; }
err()  { printf '%s\n' "  ${_Cr}✗${_CR} ${_Cr}$*${_CR}" >&2; }
hr()   { printf '%s\n' "${_CD}────────────────────────────────────────────────────────${_CR}"; }
