#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 13.M: remule-gui against a running daemon, remuled or
# the C++ amuled.
#
# The daemon runs from an aMule config directory logged into a scripted ed2k
# server (fake_ed2k_server.py, which also answers searches), sharing one
# file. First, what remule-gui's EC worker asks of it, through the same
# remule_ec::model calls (remule-ec's `gui_check` example): the connection
# and HighID, the server list, a search and its result downloaded, a link
# added, paused, resumed, set to high and cancelled, a new shared file and
# its priority, the disk space and the log. Then, with a download added and
# a search run by remulecmd, remule-gui opens on each of its pages in turn,
# under the X display it is given (Xvfb in CI), logs in with the password on
# its command line, and is left to poll for a few seconds. It must log in
# (the daemon says so), stay up, and not lose the connection; each page is
# captured as a PNG (ImageMagick's `import`) into SHOTS when that is set.
# Last, remulecmd shuts the daemon down.
#
# Usage: xvfb-run -a -s '-screen 0 1400x900x24' scripts/interop/remule-gui-on-daemon.sh
# Environment:
#   DAEMON=target/release/remuled        the daemon: remuled, or amuled
#   REMULECMD=target/release/remulecmd   the command-line client
#   REMULE_GUI=target/release/remule-gui the GUI
#   GUI_CHECK=target/release/examples/gui_check  remule-ec's gui_check
#   SHOTS=dir                            where to keep a screenshot per page
#   KEEP=1                               keep the work directory

set -uo pipefail

DAEMON=$(realpath "${DAEMON:-${REMULED:-target/release/remuled}}")
REMULECMD=$(realpath "${REMULECMD:-target/release/remulecmd}")
REMULE_GUI=$(realpath "${REMULE_GUI:-target/release/remule-gui}")
GUI_CHECK=$(realpath "${GUI_CHECK:-target/release/examples/gui_check}")
HERE=$(dirname "$(realpath "$0")")
TCP_PORT=4662
SERVER_PORT=4242
EC_PORT=4712
EC_PASS=gui

for b in "$DAEMON" "$REMULECMD" "$REMULE_GUI" "$GUI_CHECK"; do
	[ -x "$b" ] || { echo "missing $b (cargo build --release)"; exit 2; }
done
[ -n "${DISPLAY:-}" ] || { echo "no DISPLAY: run it under xvfb-run"; exit 2; }
case "$(basename "$DAEMON")" in
amuled*) KIND=amuled ;;
*) KIND=remuled ;;
esac

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

# What the daemon logged: its output, and aMule's logfile.
daemon_log() {
	cat "$WORK/daemon.log" "$CFG/logfile" 2>/dev/null
}

fail() {
	echo "FAIL: $*"
	echo "----- $KIND log (tail) -----"
	daemon_log | tail -40
	echo "----- server log (tail) -----"
	tail -30 "$WORK/server.log" 2>/dev/null || true
	for f in "$WORK"/gui-*.log; do
		[ -f "$f" ] && { echo "----- $(basename "$f") -----"; tail -20 "$f"; }
	done
	exit 1
}

cmd() {
	"$REMULECMD" -h 127.0.0.1 -p "$EC_PORT" -P "$EC_PASS" -c "$*"
}

# --- the daemon, as in amulecmd-drives-remuled.sh ----------------------------

# The fake server on this machine's own address: aMule drops a loopback
# server from server.met (CServerList::AddServer checks IsGoodIP, which
# refuses 127.0.0.0/8 whatever FilterLanIPs says).
# The address of the default route (a UDP connect sends nothing).
SERVER_IP=$(python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("10.255.255.255", 1))
print(s.getsockname()[0])' 2>/dev/null)
SERVER_IP=${SERVER_IP:-127.0.0.1}
# An address ending in .0 makes a LowID (the ID is the address with its first
# octet in the low byte: below 2^24). remuled takes a loopback server.
case "$SERVER_IP" in
*.0) [ "$KIND" = remuled ] && SERVER_IP=127.0.0.1 ;;
esac
echo "the fake server on $SERVER_IP:$SERVER_PORT"

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
TempDir=$CFG/Temp
IncomingDir=$CFG/Incoming
IPFilterAutoLoad=0
UPnPEnabled=0
GeoIPEnabled=0
GeoIPAutoUpdate=0
NewVersionCheck=0
[ExternalConnect]
AcceptExternalConnections=1
ECAddress=127.0.0.1
ECPort=$EC_PORT
ECPassword=$EC_DIGEST
EOF
python3 - "$CFG/server.met" "$SERVER_IP" "$SERVER_PORT" <<'EOF'
import socket, struct, sys
path, ip, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
name = b"remule interop server"
with open(path, "wb") as f:
    f.write(bytes([0x0E]) + struct.pack("<I", 1))
    f.write(socket.inet_aton(ip) + struct.pack("<HI", port, 1))
    f.write(struct.pack("<BHBH", 0x02, 1, 0x01, len(name)) + name)
EOF
# Offline: no server list fetched from the default addresses.
: >"$CFG/addresses.dat"
head -c 300000 /dev/urandom >"$WORK/share/gui shared file.bin"
printf '%s\n' "$WORK/share" >"$CFG/shareddir.dat"

python3 "$HERE/fake_ed2k_server.py" "$SERVER_IP" "$SERVER_PORT" >"$WORK/server.log" 2>&1 &
PIDS+=($!)
if [ "$KIND" = amuled ]; then
	"$DAEMON" --config-dir "$CFG" --log-stdout >"$WORK/daemon.log" 2>&1 &
else
	"$DAEMON" --config-dir "$CFG" >"$WORK/daemon.log" 2>&1 &
fi
DAEMON_PID=$!
PIDS+=($DAEMON_PID)
for _ in $(seq 60); do
	cmd status 2>/dev/null | grep "Connected to remule interop server" >/dev/null && break
	kill -0 "$DAEMON_PID" 2>/dev/null || fail "$KIND exited"
	sleep 1
done
cmd status | grep "Connected to remule interop server" >/dev/null || fail "$KIND never logged into the fake server"
echo "$KIND is up: $(cmd status | grep -m1 "Succeeded")"

# --- what remule-gui asks, at the model level --------------------------------------

"$GUI_CHECK" 127.0.0.1 "$EC_PORT" "$EC_PASS" "$CFG/Incoming" || fail "remule-gui's requests"

# Something on each page: a download and a search's results.
cmd "add ed2k://|file|remule%20gui%20check.iso|123456789|0123456789ABCDEF0123456789ABCDEF|/" >/dev/null
cmd "search local interop" >/dev/null
sleep 2

# --- the GUI, page by page -----------------------------------------------------

for page in networks searches transfers shared statistics; do
	before=$(daemon_log | grep -c "Access granted")
	"$REMULE_GUI" -h 127.0.0.1 -p "$EC_PORT" -P "$EC_PASS" --page "$page" \
		>"$WORK/gui-$page.log" 2>&1 &
	gui=$!
	PIDS+=($gui)
	sleep 6
	kill -0 "$gui" 2>/dev/null || fail "remule-gui exited on the $page page"
	after=$(daemon_log | grep -c "Access granted")
	[ "$after" -gt "$before" ] || fail "remule-gui did not log in ($page)"
	if [ -n "${SHOTS:-}" ]; then
		import -window root "$SHOTS/$page.png" 2>/dev/null || echo "no screenshot of $page"
	fi
	kill "$gui"
	wait "$gui" 2>/dev/null
	echo "ok: remule-gui logged in and stayed up on the $page page"
done
grep -qs "Connecting client: remule-gui" "$WORK/daemon.log" "$CFG/logfile" || fail "$KIND never saw remule-gui by name"

# --- shutdown ----------------------------------------------------------------------

cmd shutdown >/dev/null
for _ in $(seq 30); do
	kill -0 "$DAEMON_PID" 2>/dev/null || break
	sleep 1
done
kill -0 "$DAEMON_PID" 2>/dev/null && fail "$KIND did not stop on shutdown"
echo "PASS: remule-gui drove $KIND"
