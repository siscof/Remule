#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 12.1: the unmodified C++ amuleapi (aMule's REST API and
# web UI backend, itself an EC client) in front of remuled, tested with
# aMule's own curl suite (unittests/curl-tests/amuleapi).
#
# remuled runs offline, set up as aMule's CI sets up its amuled for the same
# suite: no ed2k, no Kad, External Connections on with the password the
# suite expects. The phases aMule's CI leaves out (they need the real ed2k
# network) are left out here too, and so are the ones that start an amuled
# of their own. Every other phase runs, in the suite's order, against one
# remuled.
#
# amuleapi-passing.txt lists the phases known to pass. One of them failing
# fails this script; one not listed passing is reported, to be added.
#
# Usage: scripts/interop/amuleapi-on-remuled.sh
# Environment:
#   REMULED=target/release/remuled   the daemon
#   AMULEAPI=amuleapi                aMule's REST API daemon
#   SUITE=.../curl-tests/amuleapi    aMule's curl suite (with lib/, run-all.sh)
#   KEEP=1                           keep the work directory

set -uo pipefail

REMULED=$(realpath "${REMULED:-target/release/remuled}")
AMULEAPI=${AMULEAPI:-amuleapi}
SUITE=${SUITE:?set SUITE to aMule unittests/curl-tests/amuleapi}
HERE=$(dirname "$(realpath "$0")")
PASSING="$HERE/amuleapi-passing.txt"

[ -x "$REMULED" ] || { echo "missing $REMULED (cargo build --release -p remuled)"; exit 2; }
[ -x "$AMULEAPI" ] || { echo "missing $AMULEAPI"; exit 2; }
[ -f "$SUITE/run-all.sh" ] || { echo "no run-all.sh in $SUITE"; exit 2; }

WORK=$(mktemp -d)
CONF="$WORK/amule"
mkdir -p "$CONF/Incoming" "$CONF/Temp"
cleanup() {
	[ -n "${REMULED_PID:-}" ] && kill "$REMULED_PID" 2>/dev/null
	sleep 1
	[ -n "${REMULED_PID:-}" ] && kill -9 "$REMULED_PID" 2>/dev/null
	if [ "${KEEP:-0}" = "1" ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# As aMule's CI writes it for its amuled (ccpp.yml, "start an isolated
# amuled"); the EC password is the suite's default.
printf '%s\n' /tmp >"$CONF/allowed-remote-dirs.dat"
EC_HASH=$(printf '%s' amule | md5sum | cut -d' ' -f1)
cat >"$CONF/amule.conf" <<EOF
[eMule]
Port=14662
UDPPort=14672
UDPEnable=0
Autoconnect=0
ConnectToED2K=0
ConnectToKad=0
Reconnect=0
UPnPEnabled=0
IncomingDir=$CONF/Incoming
TempDir=$CONF/Temp
[ExternalConnect]
AcceptExternalConnections=1
ECAddress=127.0.0.1
ECPort=4712
ECPassword=$EC_HASH
[WebServer]
Enabled=0
EOF

"$REMULED" --config-dir "$CONF" >"$WORK/remuled.log" 2>&1 &
REMULED_PID=$!
for _ in $(seq 60); do
	grep -q "TCP socket (ECServer) listening" "$WORK/remuled.log" && break
	sleep 0.5
done
grep -q "TCP socket (ECServer) listening" "$WORK/remuled.log" || {
	cat "$WORK/remuled.log"
	echo "remuled never listened for EC"
	exit 1
}

# aMule's CI list (they need a real ed2k search, a live connection or event
# churn a daemon with no peers never makes), and the phases that start an
# amuled of their own.
EXCLUDED=(
	00-peer-fixture.sh
	07-read-stats-and-search-results.sh
	10-refresher-lazy-ondemand.sh
	14-servers-mutations.sh
	16-networks-connect.sh
	19-search.sh
	20-etag-conditional-get.sh
	22-sse-diff-emission.sh
	24-sse-resync.sh
	28-list-pagination-sort.sh
	99-peer-fixture-teardown.sh
	26-rfc-followup-endpoints.sh
	45-all-search.sh
	49-search-metadata.sh
)
PHASES=()
for f in "$SUITE"/[0-9]*.sh; do
	f=$(basename "$f")
	skip=
	for e in "${EXCLUDED[@]}"; do
		[ "$f" = "$e" ] && skip=1 && break
	done
	[ -z "$skip" ] && PHASES+=("$f")
done
echo "running ${#PHASES[@]} phases against remuled"

AMULEAPI_BIN="$AMULEAPI" AMULE_SHARED_DIR="$CONF/Incoming" \
	bash "$SUITE/run-all.sh" "${PHASES[@]}" >"$WORK/suite.log" 2>&1
cat "$WORK/suite.log"

# "<phase> exit=<rc>" per phase (not always at the start of a line: a
# phase's last output may not end with a newline).
mapfile -t RESULTS < <(grep -oE '[0-9][0-9a-z-]*\.sh exit=[0-9]+$' "$WORK/suite.log")
declare -A RC=()
for r in "${RESULTS[@]}"; do
	RC[${r% exit=*}]=${r##*exit=}
done
mapfile -t EXPECTED < <(grep -v '^\s*#' "$PASSING" 2>/dev/null | grep -v '^\s*$')

echo "===================== against remuled ====================="
FAIL=0
for p in "${PHASES[@]}"; do
	rc=${RC[$p]:-missing}
	listed=
	for e in "${EXPECTED[@]}"; do
		[ "$e" = "$p" ] && listed=1 && break
	done
	if [ "$rc" = "0" ]; then
		if [ -n "$listed" ]; then echo "pass  $p"; else echo "pass  $p  (new: add it to amuleapi-passing.txt)"; fi
	elif [ -n "$listed" ]; then
		echo "FAIL  $p  (exit $rc; it passed before)"
		FAIL=1
	else
		echo "fail  $p  (exit $rc; not yet)"
	fi
done
if [ "$FAIL" = "1" ]; then
	echo "----- remuled log (tail) -----"
	tail -100 "$WORK/remuled.log"
	echo "a phase that passed before fails now"
	exit 1
fi
echo "no phase that passed before fails"
