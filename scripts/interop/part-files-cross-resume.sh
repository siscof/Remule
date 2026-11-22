#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 8.M: a stock aMule resumes a download remule started,
# and remule resumes one a stock aMule started.
#
# A released amuled (upstream's static build) shares a random three-part
# file through fake_ed2k_server.py, which hands it out as a source to whoever
# asks (OP_GETSOURCES). Then:
#   1. remule downloads part of it, slowly, and stops. A second amuled is
#      started on a config whose Temp holds only remule's NNN.part and
#      NNN.part.met: before it has any source it must list the download with
#      what remule had, then connect to the server and finish it.
#   2. A third amuled downloads part of it, slowly, and is shut down. remule
#      is started on that aMule's Temp: its first status line must show what
#      aMule had, and it must finish the file.
# Both finished files are compared with the shared one byte for byte.
# Nothing touches the real network; everything runs on this machine's own
# address (aMule refuses loopback servers and sources), FilterLanIPs off.
#
# Usage: scripts/interop/part-files-cross-resume.sh
# Environment:
#   REMULE=target/release/remule   the remule binary
#   SIZE=24000000                  bytes to share (default: three parts)
#   TIMEOUT=180                    seconds each side gets to finish
#   KEEP=1                         keep the work directory

set -uo pipefail

REMULE=$(realpath "${REMULE:-target/release/remule}")
SIZE=${SIZE:-24000000}
TIMEOUT=${TIMEOUT:-180}
# KiB/s while a download is meant to stop half-way.
SLOW=1024
SERVER_PORT=4242
REMULE_PORT=4663
# The second remule, a new user hash, on another port: the source aMule
# knows the first one's address with the first one's hash.
REMULE_PORT2=4664
HERE=$(dirname "$(realpath "$0")")
EC_PASS=interop

for tool in amuled amulecmd; do
	command -v "$tool" >/dev/null || { echo "missing $tool (aMule's release tarball)"; exit 2; }
done
[ -x "$REMULE" ] || { echo "missing $REMULE (cargo build --release -p remule-cli)"; exit 2; }

WORK=$(mktemp -d)
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
	echo "----- fake server -----"
	cat "$WORK/server.log" 2>/dev/null || true
	for f in "$WORK"/remule-*.log; do
		[ -f "$f" ] && { echo "----- $(basename "$f") (tail) -----"; tail -40 "$f"; }
	done
	for d in "$WORK"/amule-*; do
		[ -d "$d" ] || continue
		echo "----- $(basename "$d") logfile -----"
		grep -v "External connection\|Connecting client: aMulecmd\|Access granted\|New external\|running aMule as root\|recommended for security\|advised to run\|user instead" \
			"$d/logfile" 2>/dev/null | tail -40 || true
		echo "----- $(basename "$d") Temp -----"
		ls -la "$d/Temp" 2>/dev/null || true
	done
	exit 1
}

# The address of the default route (a UDP connect sends nothing).
IP=$(python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("10.255.255.255", 1))
print(s.getsockname()[0])' 2>/dev/null)
case "$IP" in
"" | 127.*) echo "no address but loopback"; exit 2 ;;
# The ID is the address with its first octet in the low byte: x.y.z.0 is a LowID.
*.0) echo "$IP would give a LowID"; exit 2 ;;
esac
echo "this machine: $IP"

# An aMule config: amule_config DIR NICK TCP_PORT EC_PORT MAX_DOWNLOAD
amule_config() {
	local dir=$1
	mkdir -p "$dir/Temp" "$dir/Incoming"
	cat >"$dir/amule.conf" <<EOF
[eMule]
Nick=$2
Port=$3
UDPPort=$(($3 + 10))
UDPDisable=1
TempDir=$dir/Temp
IncomingDir=$dir/Incoming
FilterLanIPs=0
ConnectToKad=0
ConnectToED2K=1
Autoconnect=0
Reconnect=0
IPFilterAutoLoad=0
UPnPEnabled=0
GeoIPEnabled=0
GeoIPAutoUpdate=0
NewVersionCheck=0
MaxUpload=0
MaxDownload=$5
[ExternalConnect]
AcceptExternalConnections=1
ECAddress=127.0.0.1
ECPort=$4
ECPassword=$(printf '%s' "$EC_PASS" | md5sum | cut -d' ' -f1)
IpFilterClients=0
IpFilterServers=0
EOF
	python3 - "$IP" "$SERVER_PORT" "$dir/server.met" <<'PY'
import socket, struct, sys
ip, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
# MET_HEADER, one server, no tags.
open(path, "wb").write(struct.pack("<BI", 0x0E, 1) + socket.inet_aton(ip) + struct.pack("<HI", port, 0))
PY
	: >"$dir/addresses.dat"
}

# amulecmd against the aMule on EC port $1.
cmd() { amulecmd -h 127.0.0.1 -p "$1" -P "$EC_PASS" -c "$2" 2>&1; }

# Start amuled on DIR, its EC on PORT; its PID in AMULE_PID.
start_amule() {
	amuled --config-dir="$1" >"$1/amuled.log" 2>&1 &
	AMULE_PID=$!
	PIDS+=($AMULE_PID)
	for _ in $(seq 1 60); do
		cmd "$2" status | grep "Succeeded" >/dev/null && return 0
		sleep 1
	done
	fail "amuled on $1 did not come up"
}

# Shut the aMule on EC port $1 down (its PID in AMULE_PID), saving its downloads.
stop_amule() {
	cmd "$1" shutdown >/dev/null
	for _ in $(seq 1 30); do
		kill -0 "$AMULE_PID" 2>/dev/null || return 0
		sleep 1
	done
	fail "aMule did not stop on shutdown"
}

# The first "[NN.N%]" amulecmd's "show dl" gives for the file, as an integer.
amule_percent() {
	cmd "$1" "show dl" | grep -o '\[[0-9.]*%\]' | sed -n 1p | tr -d '[]%' | cut -d. -f1
}

python3 "$HERE/fake_ed2k_server.py" "$IP" "$SERVER_PORT" >"$WORK/server.log" 2>&1 &
PIDS+=($!)

# --- the source ------------------------------------------------------------------

SRC="$WORK/amule-source"
amule_config "$SRC" source 4662 4712 0
NAME="cross-resume.bin"
head -c "$SIZE" /dev/urandom >"$SRC/Incoming/$NAME"
HASH_OUT=$("$REMULE" hash "$SRC/Incoming/$NAME")
LINK=$(printf '%s\n' "$HASH_OUT" | grep -m1 '^ed2k://')
HASH=$(printf '%s\n' "$LINK" | cut -d'|' -f5 | tr 'A-F' 'a-f')
echo "link: $LINK"
start_amule "$SRC" 4712
amuled --version 2>/dev/null | sed -n 1p || true
for _ in $(seq 1 60); do
	cmd 4712 "show shared" | grep "$NAME" >/dev/null && break
	sleep 1
done
cmd 4712 "connect $IP:$SERVER_PORT" >/dev/null
# aMule offers its files on its once-a-minute republish tick.
offered=0
for _ in $(seq 1 150); do
	grep -qs "offered .*$HASH" "$WORK/server.log" && { offered=1; break; }
	sleep 1
done
[ "$offered" = 1 ] || fail "the source aMule did not offer the file to the server"
echo "the source aMule shares the file through the server"

# --- 1. remule starts, aMule finishes ----------------------------------------------

"$REMULE" download "$LINK" --server "$IP:$SERVER_PORT" \
	--temp "$WORK/remule-temp" --incoming "$WORK/remule-incoming1" --config "$WORK/remule-config" \
	--port "$REMULE_PORT" --allow-lan --max-download "$SLOW" --duration 10 --status-every 2 \
	>"$WORK/remule-start.log" 2>&1
[ -f "$WORK/remule-incoming1/$NAME" ] && fail "remule finished the file: nothing left to resume"
met=$(cd "$WORK/remule-temp" && ls ./*.part.met 2>/dev/null | sed -n 1p)
[ -n "$met" ] || fail "remule left no .part.met"
part=${met%.met}
echo "remule stopped at: $(grep '%' "$WORK/remule-start.log" | tail -1)"

DL1="$WORK/amule-resumes-remule"
amule_config "$DL1" resumer 4672 4713 0
cp "$WORK/remule-temp/$part" "$WORK/remule-temp/$met" "$DL1/Temp/"
start_amule "$DL1" 4713
cmd 4713 "show dl" | grep -A1 "$NAME" | sed 's/^/  /'
p=$(amule_percent 4713)
[ -n "$p" ] || fail "aMule did not load remule's $met"
[ "$p" -gt 0 ] || fail "aMule loaded remule's $met with nothing done"
echo "ok: aMule loaded remule's download at $p%, before any source"
cmd 4713 "connect $IP:$SERVER_PORT" >/dev/null
start=$(date +%s)
until [ -f "$DL1/Incoming/$NAME" ]; do
	[ $(($(date +%s) - start)) -ge "$TIMEOUT" ] && { cmd 4713 "show dl"; fail "aMule did not finish remule's download in ${TIMEOUT}s"; }
	sleep 2
done
sleep 1
cmp -s "$DL1/Incoming/$NAME" "$SRC/Incoming/$NAME" || fail "the file aMule finished from remule's .part differs"
echo "ok: aMule finished remule's download after $(($(date +%s) - start))s, byte for byte"
stop_amule 4713

# --- 2. aMule starts, remule finishes ----------------------------------------------

DL2="$WORK/amule-starts"
amule_config "$DL2" starter 4682 4714 "$SLOW"
start_amule "$DL2" 4714
cmd 4714 "connect $IP:$SERVER_PORT" >/dev/null
cmd 4714 "add $LINK" >/dev/null
start=$(date +%s)
while :; do
	p=$(amule_percent 4714)
	[ -n "$p" ] && [ "$p" -ge 20 ] && break
	[ $(($(date +%s) - start)) -ge "$TIMEOUT" ] && { cmd 4714 "show dl"; fail "aMule never got to 20%"; }
	sleep 1
done
cmd 4714 "show dl" | grep -A1 "$NAME" | sed 's/^/  /'
stop_amule 4714
[ -f "$DL2/Incoming/$NAME" ] && fail "aMule finished the file: nothing left to resume"
echo "ok: aMule stopped at $p% or more; its Temp: $(cd "$DL2/Temp" && ls | tr '\n' ' ')"

start=$(date +%s)
REMULE_TRACE=1 "$REMULE" download --server "$IP:$SERVER_PORT" \
	--temp "$DL2/Temp" --incoming "$WORK/remule-incoming2" --config "$WORK/remule-config2" \
	--port "$REMULE_PORT2"--allow-lan --duration "$TIMEOUT" --status-every 5 \
	>"$WORK/remule-resume.log" 2>&1
echo "remule exited with $? after $(($(date +%s) - start))s"
first=$(grep -m1 "% .*$NAME" "$WORK/remule-resume.log")
echo "remule's first status: $first"
pct=$(printf '%s\n' "$first" | sed -n 's/^\[ *[0-9]*s\] *\([0-9]*\)\..*/\1/p')
[ -n "$pct" ] || fail "remule did not resume aMule's download"
[ "$pct" -gt 0 ] || fail "remule resumed aMule's download with nothing done"
[ -f "$WORK/remule-incoming2/$NAME" ] || fail "remule did not finish aMule's download in ${TIMEOUT}s"
cmp -s "$WORK/remule-incoming2/$NAME" "$SRC/Incoming/$NAME" || fail "the file remule finished from aMule's .part differs"
echo "ok: remule resumed aMule's download at $pct% and finished it, byte for byte"

echo "PASS: aMule and remule each resumed and finished a download the other started"
