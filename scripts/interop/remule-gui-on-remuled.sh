#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 13.M: remule-gui against a running remuled.
#
# remuled runs from an aMule config directory logged into a scripted ed2k
# server (fake_ed2k_server.py, which also answers searches), sharing one
# file, with one download added and one search run by remulecmd. remule-gui
# then opens on each of its pages in turn, under the X display it is given
# (Xvfb in CI), logs in with the password on its command line, and is left
# to poll for a few seconds. It must log in (remuled says so), stay up, and
# not lose the connection; each page is captured as a PNG (ImageMagick's
# `import`) into SHOTS when that is set.
#
# Usage: xvfb-run -a -s '-screen 0 1400x900x24' scripts/interop/remule-gui-on-remuled.sh
# Environment:
#   REMULED=target/release/remuled       the daemon
#   REMULECMD=target/release/remulecmd   the command-line client
#   REMULE_GUI=target/release/remule-gui the GUI
#   SHOTS=dir                            where to keep a screenshot per page
#   KEEP=1                               keep the work directory

set -uo pipefail

REMULED=$(realpath "${REMULED:-target/release/remuled}")
REMULECMD=$(realpath "${REMULECMD:-target/release/remulecmd}")
REMULE_GUI=$(realpath "${REMULE_GUI:-target/release/remule-gui}")
HERE=$(dirname "$(realpath "$0")")
TCP_PORT=4662
SERVER_PORT=4242
EC_PORT=4712
EC_PASS=gui

for b in "$REMULED" "$REMULECMD" "$REMULE_GUI"; do
	[ -x "$b" ] || { echo "missing $b (cargo build --release)"; exit 2; }
done
[ -n "${DISPLAY:-}" ] || { echo "no DISPLAY: run it under xvfb-run"; exit 2; }

WORK=$(mktemp -d)
CFG="$WORK/amule"
mkdir -p "$CFG" "$WORK/share"
[ -n "${SHOTS:-}" ] && mkdir -p "$SHOTS"

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
	for f in remuled server; do
		echo "----- $f log (tail) -----"
		tail -30 "$WORK/$f.log" 2>/dev/null || true
	done
	for f in "$WORK"/gui-*.log; do
		[ -f "$f" ] && { echo "----- $(basename "$f") -----"; tail -20 "$f"; }
	done
	exit 1
}

cmd() {
	"$REMULECMD" -h 127.0.0.1 -p "$EC_PORT" -P "$EC_PASS" -c "$*"
}

# --- remuled, as in amulecmd-drives-remuled.sh -------------------------------

EC_DIGEST=$(printf '%s' "$EC_PASS" | md5sum | cut -d' ' -f1)
cat >"$CFG/amule.conf" <<EOF
[eMule]
Nick=remule-gui-check
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
head -c 300000 /dev/urandom >"$WORK/share/gui shared file.bin"
printf '%s\n' "$WORK/share" >"$CFG/shareddir.dat"

python3 "$HERE/fake_ed2k_server.py" 127.0.0.1 "$SERVER_PORT" >"$WORK/server.log" 2>&1 &
PIDS+=($!)
"$REMULED" --config-dir "$CFG" >"$WORK/remuled.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 60); do
	grep -q "TCP socket (ECServer) listening" "$WORK/remuled.log" && break
	sleep 1
done
grep -q "TCP socket (ECServer) listening" "$WORK/remuled.log" || fail "remuled never listened for EC"
for _ in $(seq 30); do
	cmd status 2>/dev/null | grep -q "Connected to" && break
	sleep 1
done
cmd status | grep -q "Connected to" || fail "remuled never logged into the server"

# Something on each page: a download and a search's results.
cmd "add ed2k://|file|remule%20gui%20check.iso|123456789|0123456789ABCDEF0123456789ABCDEF|/" >/dev/null
cmd "search local interop" >/dev/null
sleep 2

# --- the GUI, page by page -----------------------------------------------------

for page in networks searches transfers shared statistics; do
	before=$(grep -c "Access granted" "$WORK/remuled.log")
	"$REMULE_GUI" -h 127.0.0.1 -p "$EC_PORT" -P "$EC_PASS" --page "$page" \
		>"$WORK/gui-$page.log" 2>&1 &
	gui=$!
	PIDS+=($gui)
	sleep 6
	kill -0 "$gui" 2>/dev/null || fail "remule-gui exited on the $page page"
	after=$(grep -c "Access granted" "$WORK/remuled.log")
	[ "$after" -gt "$before" ] || fail "remule-gui did not log in ($page)"
	if [ -n "${SHOTS:-}" ]; then
		import -window root "$SHOTS/$page.png" 2>/dev/null || echo "no screenshot of $page"
	fi
	kill "$gui"
	wait "$gui" 2>/dev/null
	echo "ok: remule-gui logged in and stayed up on the $page page"
done
grep -q "Connecting client: remule-gui" "$WORK/remuled.log" || fail "remuled never saw remule-gui by name"
echo "PASS: remule-gui drove remuled"
