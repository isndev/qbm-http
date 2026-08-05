#!/usr/bin/env bash
#
# doc-lint.sh — documentation anti-drift guard for the qbm-http module.
#
# Fails on: retired tokens in docs, broken internal Markdown links, cross-repo URLs naming
# a dead repo or a non-released ref, missing module governance files. Warns on: pages missing a "Verified-against" marker.
# Module-wide policy (versioning, support) lives in the qb framework; this guard
# checks only qbm-http's own Markdown (README.md, readme/**, CHANGELOG/SECURITY/CONTRIBUTING).
#
# Usage:  ./scripts/doc-lint.sh   (from the qbm-http root)
#
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}" || exit 2
fail=0; warn=0
red(){ printf '\033[31m%s\033[0m\n' "$1"; }; grn(){ printf '\033[32m%s\033[0m\n' "$1"; }; ylw(){ printf '\033[33m%s\033[0m\n' "$1"; }

doc_files(){ { echo "README.md"; echo "CHANGELOG.md"; echo "SECURITY.md"; echo "CONTRIBUTING.md"; find readme -name '*.md' 2>/dev/null; } | sort -u | while read -r f; do [ -f "$f" ] && echo "$f"; done; }

# Expected qb version for the "Verified-against" markers.
#
# WHERE THIS COMES FROM, and why it is not qb's file directly: this repo is independent and
# its own CI checks out ONLY this repo -- there is no qb tree to read. So the expected value
# has to be derivable from this repo alone, and the one authoritative version here is
# project(qbm-http VERSION ...) in CMakeLists.txt. That is a legitimate source rather than a
# convenient one: the module is not standalone-configurable (it calls qb_register_module /
# qb_add_test, which an installed qb does not ship), so its version only ever means "the qb
# this module was built against", and the modules are versioned in lockstep with the framework
# by policy.
#
# When a qb checkout IS reachable -- the qb-dev superproject layout, or an explicit QB_ROOT --
# the two are cross-checked below, so lockstep drift fails in the one place it can actually be
# observed. Being unable to determine the version is a HARD STOP, never a skip: a lint that
# quietly passes when it cannot find its expected value is indistinguishable from the
# unvalidated marker it replaces, which is the exact state this closes (129 markers sat at
# "qb 2.6.0" across two version bumps, because only their EXISTENCE was ever checked).
EXPECTED_VERSION="$(sed -n 's/^[[:space:]]*project(qbm-http[[:space:]]\{1,\}VERSION[[:space:]]\{1,\}\([0-9][0-9.]*\)).*/\1/p' \
                    CMakeLists.txt 2>/dev/null | head -1)"
if [ -z "${EXPECTED_VERSION}" ]; then
  red "doc-lint: cannot read project(qbm-http VERSION ...) from CMakeLists.txt"
  red "          refusing to validate Verified-against markers against an unknown version"
  exit 2
fi
VERSION_SOURCE="CMakeLists.txt"
QB_CONFIG=""
for _cand in "${QB_ROOT:-}/cmake/qbConfig.cmake" "../../qb/cmake/qbConfig.cmake"; do
  case "${_cand}" in /cmake/qbConfig.cmake) continue ;; esac      # QB_ROOT unset
  [ -f "${_cand}" ] && { QB_CONFIG="${_cand}"; break; }
done
if [ -n "${QB_CONFIG}" ]; then
  _qbver="$(sed -n 's/^[[:space:]]*set(QB_FRAMEWORK_VERSION[[:space:]]*"\([0-9][0-9.]*\)").*/\1/p' "${QB_CONFIG}" | head -1)"
  if [ -z "${_qbver}" ]; then
    red "doc-lint: ${QB_CONFIG} is present but QB_FRAMEWORK_VERSION could not be parsed"
    exit 2
  fi
  if [ "${_qbver}" != "${EXPECTED_VERSION}" ]; then
    red "doc-lint: lockstep drift -- CMakeLists.txt says qbm-http ${EXPECTED_VERSION},"
    red "          but ${QB_CONFIG} says qb ${_qbver}"
    exit 2
  fi
  VERSION_SOURCE="${QB_CONFIG}"
fi

echo "== 1. Forbidden token scan =="
FORBIDDEN='qb::Timestamp|qb::Duration|qb::TimePoint|to_timestamp\(|to_time_point\(|get_ptr<|create_[a-z_]+_middleware\(|coro_handler<|coro_middleware<|MEMBER_HANDLER\('
is_allowed(){ case "$1" in CHANGELOG.md|CONTRIBUTING.md) return 0;; *) return 1;; esac; }
hits=0
while read -r f; do
  is_allowed "$f" && continue
  if grep -nE "${FORBIDDEN}" "$f" >/dev/null 2>&1; then
    grep -nE "${FORBIDDEN}" "$f" | while IFS= read -r l; do red "  ${f}: ${l}"; done
    hits=1
  fi
done < <(doc_files)
[ "$hits" -eq 0 ] && grn "  no forbidden tokens" || fail=1

echo "== 1b. Citation integrity (src: file + line ranges) =="
if command -v python3 >/dev/null 2>&1; then
  python3 "${SCRIPT_DIR}/cite-check.py" || fail=1
else
  # HARD FAILURE, not a skip. This used to print a yellow "skipping citation check" and
  # carry on, which meant a run with no python3 checked the forbidden-token scan, the
  # links and the governance files, printed no red, and exited 0 -- while every citation
  # in the book went unverified. That is the exact shape of defect this whole battery
  # exists to catch: a guard that degrades into a pass. cite-check.py is not optional
  # here, so its interpreter is not optional either.
  red "  python3 not found — cite-check.py cannot run, and this lint does not pass without it"
  red "  install python3 (>= 3.8) and re-run; do NOT treat a skipped citation check as green"
  fail=1
fi

echo "== 2. Internal link check =="
while read -r f; do
  dir="$(dirname "$f")"
  awk 'BEGIN{c=0} /^[[:space:]]*```/{c=!c; next} !c{print}' "$f" 2>/dev/null \
    | grep -oE '\]\([^) ]+\)' 2>/dev/null | sed -E 's/^\]\(//; s/\)$//' | while IFS= read -r t; do
    case "$t" in http://*|https://*|mailto:*|\#*) continue;; esac
    p="${t%%#*}"; [ -z "$p" ] && continue
    case "$p" in /*) r="${ROOT}${p}";; *) r="${dir}/${p}";; esac
    [ ! -e "$r" ] && { red "  ${f} -> ${t} (missing)"; echo X >> /tmp/qbmhttp-doclint-broken.$$; }
  done
done < <(doc_files)
broken=0; [ -f /tmp/qbmhttp-doclint-broken.$$ ] && { broken=$(wc -l < /tmp/qbmhttp-doclint-broken.$$); rm -f /tmp/qbmhttp-doclint-broken.$$; }
[ "${broken:-0}" -eq 0 ] && grn "  all internal links resolve" || fail=1

echo "== 2b. Cross-repo URL check (repo name + git ref of absolute isndev links) =="
# Section 2 deliberately skips http(s) targets, so a link into a SIBLING repo was validated by
# nothing at all. That blind spot shipped 35 dead URLs across the doc books: they named
# github.com/isndev/cube -- the repo's old PRIVATE name, since published as isndev/qb -- on
# branch c++23, which no longer exists. Both halves 404 for a reader of the released docs, and
# four green doc-lint runs never saw them.
#
# The check stays offline (no network, no API rate limit, a few milliseconds): it does not
# resolve the URL, it validates the only two parts that rot -- the repository name and the git
# ref. Docs must cite the RELEASED line, so `main` or a 40-hex permalink; a link into a moving
# development branch is rejected because it silently rots again on the next merge.
ISNDEV_REPOS='qb qb-dev qb-ev qb-examples qbm-http qbm-pgsql qbm-redis'
while read -r f; do
  grep -oE 'https://github\.com/isndev/[A-Za-z0-9_.+-]+(/(blob|tree|raw)/[^/)" ]+)?' "$f" 2>/dev/null \
    | while IFS= read -r u; do
    repo="$(printf '%s\n' "$u" | cut -d/ -f5)"; repo="${repo%.git}"
    ref="$(printf '%s\n' "$u" | cut -d/ -f7)"
    case " ${ISNDEV_REPOS} " in
      *" ${repo} "*) ;;
      *) red "  ${f}: unknown repository 'isndev/${repo}' -> ${u}"; echo X >> /tmp/qbmhttp-doclint-badurl.$$ ;;
    esac
    [ -z "${ref}" ] && continue
    [ "${ref}" = "main" ] && continue
    if [ "${#ref}" -eq 40 ]; then
      case "${ref}" in *[!0-9a-f]*) ;; *) continue ;; esac    # 40-hex commit permalink: pinned, fine
    fi
    red "  ${f}: ref '${ref}' is not main or a permalink -> ${u}"; echo X >> /tmp/qbmhttp-doclint-badurl.$$
  done
done < <(doc_files)
badurl=0; [ -f /tmp/qbmhttp-doclint-badurl.$$ ] && { badurl=$(wc -l < /tmp/qbmhttp-doclint-badurl.$$); rm -f /tmp/qbmhttp-doclint-badurl.$$; }
[ "${badurl:-0}" -eq 0 ] && grn "  all cross-repo URLs name a live repo on main" || fail=1

echo "== 3. Module governance presence =="
missing=0
for g in README.md CHANGELOG.md SECURITY.md CONTRIBUTING.md LICENSE; do
  [ ! -f "$g" ] && { red "  missing: ${g}"; missing=1; }
done
[ "$missing" -eq 0 ] && grn "  module governance present" || fail=1

echo "== 4. Verified-against marker (missing: warning, wrong version: error) =="
nomarker=0; badmarker=0
while read -r f; do
  case "$f" in CHANGELOG.md) continue;; esac
  marker="$(grep -m1 'Verified-against' "$f" 2>/dev/null)"
  if [ -z "${marker}" ]; then
    ylw "  no Verified-against: ${f}"; nomarker=$((nomarker+1)); continue
  fi
  # Rightmost "qb <x.y.z>": this module's marker form is "qbm-http @ qb 3.0.0", and "qbm"
  # never matches because the pattern requires the space after "qb".
  found="$(printf '%s\n' "${marker}" | grep -oE 'qb [0-9]+\.[0-9]+\.[0-9]+' | tail -1 | awk '{print $2}')"
  if [ -z "${found}" ]; then
    red "  ${f}: Verified-against names no qb version (expected qb ${EXPECTED_VERSION}): ${marker}"
    badmarker=$((badmarker+1))
  elif [ "${found}" != "${EXPECTED_VERSION}" ]; then
    red "  ${f}: Verified-against says qb ${found}, but ${VERSION_SOURCE} says qb ${EXPECTED_VERSION}"
    badmarker=$((badmarker+1))
  fi
done < <(doc_files)
[ "$nomarker" -ne 0 ] && warn=1
if [ "$badmarker" -ne 0 ]; then
  red "  ${badmarker} page(s) verified against a qb version that is not ${EXPECTED_VERSION}"
  fail=1
elif [ "$nomarker" -eq 0 ]; then
  grn "  all pages carry a Verified-against marker naming qb ${EXPECTED_VERSION}"
fi

echo
if [ "$fail" -ne 0 ]; then red "doc-lint: FAILED"; exit 1; fi
[ "$warn" -ne 0 ] && ylw "doc-lint: passed with warnings" || grn "doc-lint: passed"
exit 0
