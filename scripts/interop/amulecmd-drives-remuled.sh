#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 11.M: the unmodified C++ amulecmd drives remuled.
#
# remuled runs from an aMule config directory with External Connections
# on, a legacy ECPassword (migrated at start, as aMule 3.3 migrates it), one
# server in server.met (fake_ed2k_server.py, which also answers searches)
# and a shared folder. amulecmd, built from the aMule-org source remule is
# ported from, logs in with the SRP login and runs what a user would:
# status, servers, shared files, adding, pausing, resuming and cancelling a
# download, a search and downloading its result, and shutdown. Each answer
# is checked against what remuled must have said. Nothing touches the real
# network.
#
# Usage: scripts/interop/amulecmd-drives-remuled.sh
# Environment:
#   REMULED=target/release/remuled   the daemon
#   AMULECMD=amulecmd                aMule's command-line client
#   KEEP=1                           keep the work directory

set -euo pipefail

REMULED=$(realpath "${REMULED:-target/release/remuled}")
AMULECMD=${AMULECMD:-amulecmd}
HERE=$(dirname "$(realpath "$0")")
TCP_PORT=4662
SERVER_PORT=4242
EC_PORT=4712
EC_PASS=interop

command -v "$AMULECMD" >/dev/null || { echo "missing $AMULECMD"; exit 2; }
[ -x "$REMULED" ] || { echo "missing $REMULED (cargo build --release -p remuled)"; exit 2; }

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

dump_logs() {
	echo "----- remuled log -----"
	cat "$WORK/remuled.log" || true
	echo "----- fake server -----"
	cat "$WORK/server.log" || true
	echo "----- amule.conf -----"
	cat "$CFG/amule.conf" || true
}

fail() {
	echo "FAIL: $*"
	dump_logs
	exit 1
}

# One amulecmd command; its output on stdout, also kept in $WORK/last.
cmd() {
	"$AMULECMD" -h 127.0.0.1 -p "$EC_PORT" -P "$EC_PASS" -c "$*" >"$WORK/last" 2>&1 || true
	echo "\$ amulecmd -c '$*'" >>"$WORK/session.log"
	cat "$WORK/last" >>"$WORK/session.log"
	cat "$WORK/last"
}

# Run a command until its output matches (grep -E -i), at most N seconds.
expect() {
	local secs=$1 pattern=$2
	shift 2
	for _ in $(seq "$secs"); do
		if cmd "$@" | grep -Eiq -- "$pattern"; then
			echo "ok: '$*' says /$pattern/"
			return 0
		fi
		sleep 1
	done
	echo "----- last output of '$*' -----"
	cat "$WORK/last"
	fail "'$*' never said /$pattern/"
}

# ... and until it no longer does.
expect_not() {
	local secs=$1 pattern=$2
	shift 2
	for _ in $(seq "$secs"); do
		if ! cmd "$@" | grep -Eiq -- "$pattern"; then
			echo "ok: '$*' no longer says /$pattern/"
			return 0
		fi
		sleep 1
	done
	cat "$WORK/last"
	fail "'$*' still says /$pattern/"
}

# --- the config directory, as aMule would leave it -------------------------

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
# server.met: version 0x0E, one server with its name (ST_SERVERNAME).
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

# --- start ---------------------------------------------------------------------

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
grep -q "ECPasswordVerifier=v1:15:8:1:" "$CFG/amule.conf" || fail "the EC password was not migrated"
grep -q "^ECPassword=" "$CFG/amule.conf" && fail "the legacy ECPassword was kept"
echo "remuled is up; $("$AMULECMD" --version 2>&1 | head -1)"

# --- what a user does ----------------------------------------------------------

# Status: logged into the fake server.
expect 30 "eD2k: Connected to remule interop server \[127\.0\.0\.1:$SERVER_PORT\] with HighID" status
# A wrong password is refused.
"$AMULECMD" -h 127.0.0.1 -p "$EC_PORT" -P wrong -c status >"$WORK/wrong" 2>&1 || true
grep -Eiq "wrong password|authentication failed|denied" "$WORK/wrong" || {
	cat "$WORK/wrong"
	fail "a wrong password was not refused"
}
echo "ok: a wrong password is refused"

expect 10 "127\.0\.0\.1:$SERVER_PORT|127\.0\.0\.1.*$SERVER_PORT" show servers
expect 60 "interop shared file\.bin" show shared
# The statistics tree, as amulecmd prints it.
expect 10 "Number of Shared Files: 1" statistics

# A download from a link: listed, paused, resumed, cancelled.
HASH=0123456789ABCDEF0123456789ABCDEF
cmd "add ed2k://|file|interop%20link.iso|123456789|$HASH|/" >/dev/null
expect 10 "interop link\.iso" show dl
cmd "pause $HASH" >/dev/null
expect 10 "paused" show dl
cmd "resume $HASH" >/dev/null
expect_not 10 "paused" show dl
cmd "cancel $HASH" >/dev/null
expect_not 10 "interop link\.iso" show dl
[ -z "$(ls "$CFG/Temp"/*.part.met 2>/dev/null)" ] || fail "the cancelled download left its files"

# A search on the server, and its result downloaded.
cmd "search local interop" >/dev/null
expect 20 "remule interop result\.iso" results
cmd "download 0" >/dev/null
expect 10 "remule interop result\.iso" show dl

# Shutdown: remuled stops and saves.
cmd shutdown >/dev/null
for _ in $(seq 30); do
	kill -0 "$REMULED_PID" 2>/dev/null || break
	sleep 1
done
kill -0 "$REMULED_PID" 2>/dev/null && fail "remuled did not stop on shutdown"
wait "$REMULED_PID" || fail "remuled exited with an error"
grep -q "shutdown requested" "$WORK/remuled.log" || fail "no shutdown in the log"
echo "----- the session -----"
cat "$WORK/session.log"
echo "PASS: amulecmd drove remuled"
