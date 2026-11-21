#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 11.9: remulecmd, amulecmd ported to Rust, prints what
# the unmodified C++ amulecmd prints.
#
# remuled runs as in amulecmd-drives-remuled.sh: an aMule config directory
# with External Connections on, one server in server.met (the fake server,
# which also answers searches) and a shared folder. Each command runs once
# with amulecmd and once with remulecmd, one after the other, and the two
# outputs must be the same, byte for byte, but for:
#   - the line naming the program ("This is amulecmd ..."),
#   - search IDs, which the daemon hands out one a search,
#   - in the statistics tree, the numbers, which move between two runs.
# Commands that change something run with one of the two, and both then
# compare what the daemon shows. Nothing touches the real network.
#
# Usage: scripts/interop/remulecmd-matches-amulecmd.sh
# Environment:
#   REMULED=target/release/remuled       the daemon
#   REMULECMD=target/release/remulecmd   the port
#   AMULECMD=amulecmd                    aMule's command-line client
#   KEEP=1                               keep the work directory

set -euo pipefail

REMULED=$(realpath "${REMULED:-target/release/remuled}")
REMULECMD=$(realpath "${REMULECMD:-target/release/remulecmd}")
AMULECMD=${AMULECMD:-amulecmd}
HERE=$(dirname "$(realpath "$0")")
TCP_PORT=4662
SERVER_PORT=4242
EC_PORT=4712
EC_PASS=interop

command -v "$AMULECMD" >/dev/null || { echo "missing $AMULECMD"; exit 2; }
[ -x "$REMULED" ] || { echo "missing $REMULED (cargo build --release -p remuled)"; exit 2; }
[ -x "$REMULECMD" ] || { echo "missing $REMULECMD (cargo build --release -p remulecmd)"; exit 2; }

WORK=$(mktemp -d)
CFG="$WORK/amule"
mkdir -p "$CFG" "$WORK/share"

PIDS=()
cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	sleep 1
	for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
	if [ "${KEEP:-0}" = "1" ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*"
	echo "----- remuled log -----"
	cat "$WORK/remuled.log" || true
	exit 1
}

# --- the config directory and remuled, as in amulecmd-drives-remuled.sh -----

EC_DIGEST=$(printf '%s' "$EC_PASS" | md5sum | cut -d' ' -f1)
cat >"$CFG/amule.conf" <<EOF
[eMule]
Nick=remuled-interop
Port=$TCP_PORT
UDPPort=4672
ConnectToKad=0
ConnectToED2K=1
Autoconnect=1
Reconnect=1
FilterLanIPs=0
[ExternalConnect]
AcceptExternalConnections=1
ECAddress=127.0.0.1
ECPort=$EC_PORT
ECPassword=$EC_DIGEST
EOF
python3 - "$CFG/server.met" "$SERVER_PORT" <<'EOF'
import socket, struct, sys
path, port = sys.argv[1], int(sys.argv[2])
name = b"remule interop server"
with open(path, "wb") as f:
    f.write(bytes([0x0E]) + struct.pack("<I", 1))
    f.write(socket.inet_aton("127.0.0.1") + struct.pack("<HI", port, 1))
    f.write(struct.pack("<BHBH", 0x02, 1, 0x01, len(name)) + name)
EOF
head -c 300000 /dev/urandom >"$WORK/share/interop shared file.bin"
printf '%s\n' "$WORK/share" >"$CFG/shareddir.dat"

python3 "$HERE/fake_ed2k_server.py" 127.0.0.1 "$SERVER_PORT" >"$WORK/server.log" 2>&1 &
PIDS+=($!)
"$REMULED" --config-dir "$CFG" >"$WORK/remuled.log" 2>&1 &
REMULED_PID=$!
PIDS+=($REMULED_PID)
for _ in $(seq 60); do
	grep -q "TCP socket (ECServer) listening" "$WORK/remuled.log" && break
	kill -0 "$REMULED_PID" 2>/dev/null || fail "remuled exited"
	sleep 1
done
grep -q "TCP socket (ECServer) listening" "$WORK/remuled.log" || fail "remuled never listened for EC"

# --- running both --------------------------------------------------------------

# One command with one client; its output on stdout.
run() {
	local client=$1
	shift
	"$client" -h 127.0.0.1 -p "$EC_PORT" -P "$EC_PASS" "$@" 2>&1 || true
}

# What may differ: the program's name and version, and search IDs.
normalize() {
	sed -E -e '/^This is (amulecmd|remulecmd) /d' -e 's/\(id [0-9]+\)/(id N)/'
}

# The statistics tree moves between two runs: its numbers are not compared.
normalize_numbers() {
	normalize | sed -E 's/[0-9]+([.:][0-9]+)*/N/g'
}

MISMATCHES=0
N=0
# compare [filter] COMMAND...: the same command through both, compared.
compare() {
	local filter=normalize
	if [ "$1" = "--numbers" ]; then
		filter=normalize_numbers
		shift
	elif [ "$1" = "--head" ]; then
		filter="normalize_head"
		shift
	fi
	N=$((N + 1))
	run "$AMULECMD" -c "$*" | $filter >"$WORK/a.$N"
	run "$REMULECMD" -c "$*" | $filter >"$WORK/r.$N"
	if cmp -s "$WORK/a.$N" "$WORK/r.$N"; then
		echo "same: '$*' ($(wc -l <"$WORK/a.$N") lines)"
	else
		echo "DIFFERENT: '$*' (- amulecmd, + remulecmd)"
		diff -u "$WORK/a.$N" "$WORK/r.$N" | tail -n +3 || true
		MISMATCHES=$((MISMATCHES + 1))
	fi
}

# The first lines of the log, which do not grow between the two runs.
normalize_head() {
	normalize | head -n 8
}

# Help, which needs no daemon: the first line is the program and version.
compare_help() {
	N=$((N + 1))
	"$AMULECMD" -c "$*" 2>&1 | tail -n +2 >"$WORK/a.$N" || true
	"$REMULECMD" -c "$*" 2>&1 | tail -n +2 >"$WORK/r.$N" || true
	if cmp -s "$WORK/a.$N" "$WORK/r.$N"; then
		echo "same: '$*' ($(wc -l <"$WORK/a.$N") lines)"
	else
		echo "DIFFERENT: '$*' (- amulecmd, + remulecmd)"
		diff -u "$WORK/a.$N" "$WORK/r.$N" | tail -n +3 || true
		MISMATCHES=$((MISMATCHES + 1))
	fi
}

# Wait until remuled is on the server, as amulecmd reports it.
for _ in $(seq 30); do
	run "$AMULECMD" -c status | grep -q "with HighID" && break
	sleep 1
done
for _ in $(seq 60); do
	run "$AMULECMD" -c "show shared" | grep -q "interop shared file" && break
	sleep 1
done

echo "amulecmd: $("$AMULECMD" --version 2>&1 | head -1)"
echo "remulecmd: $("$REMULECMD" --version 2>&1 | head -1)"

# --- help ------------------------------------------------------------------------

compare_help help
compare_help help search
compare_help help set ipfilter
compare_help help show
compare_help help get ipfilter state
compare_help help servers
compare_help help nothing
compare_help help show nothing

# --- reading -----------------------------------------------------------------------

compare status
compare show servers
compare show shared
compare show dl
compare show ul
compare --numbers statistics
compare --numbers statistics 3
compare --head show log
compare get ipfilter
compare get ipfilter state
compare get ipfilter state clients
compare get ipfilter state servers
compare get ipfilter level
compare get bwlimits
compare get endgame
compare search list
compare stats
compare getiplevel

# --- what is refused -----------------------------------------------------------------

compare frobnicate
compare show
compare show nothing
compare status now
compare get
compare set ipfilter level 300
compare set ipfilter level x
compare set bwlimit up x
compare set endgame maybe
compare statistics 300
compare priority high 123
compare priority low 00000000000000000000000000000000
compare pause
compare search linux
compare search local
compare search local --min-size
compare search local --type Iso
compare search kad x --title "'two words'"
compare search kad x --title "'unterminated"
compare download x
compare search stop 0
compare search stop x
compare connect :4661
compare setipfilter maybe

# --- changing things, then reading them back -------------------------------------------

compare set bwlimit up 20
compare set bwlimit down 300
compare setupbwlimit 25
compare set ipfilter servers off
compare set ipfilter clients on
compare set ipfilter on
compare iplevel 127
compare set endgame on
compare set endgame off

HASH=0123456789ABCDEF0123456789ABCDEF
run "$REMULECMD" -c "add ed2k://|file|interop%20link.iso|123456789|$HASH|/" >/dev/null
compare show dl
compare pause $HASH
compare show dl
compare pause interop link.iso
compare resume 001.part.met
compare resume 001
compare show dl
compare priority high $HASH
compare show dl
compare priority auto $HASH
compare show dl
compare pause all
compare show dl

# A search on the fake server, from each client, then its results.
compare search local interop
for _ in $(seq 20); do
	run "$AMULECMD" -c results | grep -q "remule interop result" && break
	sleep 1
done
compare results
compare progress
compare search list
compare results 1
compare progress 1
compare results 99
compare progress 99
run "$REMULECMD" -c "download 0" >/dev/null
compare show dl
compare search stop 1
compare search more 1
compare search list

run "$AMULECMD" -c "cancel $HASH" >/dev/null
compare show dl
compare reload shared
compare show shared
compare disconnect ed2k
compare status
compare connect 127.0.0.1:$SERVER_PORT
for _ in $(seq 30); do
	run "$AMULECMD" -c status | grep -q "with HighID" && break
	sleep 1
done
compare status

# --- shutdown, through remulecmd ------------------------------------------------------------

run "$REMULECMD" -c shutdown >"$WORK/shutdown"
for _ in $(seq 30); do
	kill -0 "$REMULED_PID" 2>/dev/null || break
	sleep 1
done
kill -0 "$REMULED_PID" 2>/dev/null && fail "remuled did not stop on remulecmd's shutdown"
wait "$REMULED_PID" || fail "remuled exited with an error"

if [ "$MISMATCHES" -ne 0 ]; then
	fail "$MISMATCHES of $N commands printed something else"
fi
echo "PASS: remulecmd printed what amulecmd printed, for all $N commands"
