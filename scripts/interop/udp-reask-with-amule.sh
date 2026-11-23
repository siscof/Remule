#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 8.6 and 4.M: eD2k client UDP with a stock aMule. A
# downloader waiting in an uploader's queue asks again over UDP
# (OP_REASKFILEPING) shortly before its TCP reask is due, and the uploader
# answers with its queue rank (OP_REASKACK); both obfuscated, keyed on the
# receiver's user hash and the sender's public IP.
#
# The uploader gets two slots (a low upload limit) and two remule
# downloaders take them, so the asker waits in its queue. Everything logs
# into fake_ed2k_server.py for a HighID (a firewalled client asks nothing
# over UDP); the sources are in the links. Nothing touches the real
# network.
#
#   DIRECTION=remule-asks  aMule shares; remule waits in its queue and asks
#                          over UDP (remule --reask 120: the UDP reask goes
#                          out at 100 s). Its trace must show the ping going
#                          out obfuscated and aMule's rank coming back.
#   DIRECTION=amule-asks   remule shares; aMule waits in its queue and asks
#                          over UDP after SourceReaskMinutes (set to 2) less
#                          20 s. remule's trace must show the ping coming in
#                          obfuscated and the rank going back. Needs an aMule
#                          with SourceReaskMinutes (aMule-org 688c51eb) whose
#                          least is lowered from 15 to 2 (CI patches
#                          SourceSearchLimits.h); about 3 minutes.
#
# Usage: DIRECTION=remule-asks scripts/interop/udp-reask-with-amule.sh
# Environment:
#   REMULE=target/release/remule   the remule binary
#   AMULED=amuled AMULECMD=amulecmd
#   KEEP=1                         keep the work directory

set -uo pipefail

REMULE=$(realpath "${REMULE:-target/release/remule}")
AMULED=${AMULED:-amuled}
AMULECMD=${AMULECMD:-amulecmd}
DIRECTION=${DIRECTION:-remule-asks}
SIZE=24000000
AMULE_TCP=4662
AMULE_UDP=4672
SERVER_PORT=4242
EC_PORT=4712
EC_PASS=interop
HERE=$(dirname "$(realpath "$0")")

for tool in "$AMULED" "$AMULECMD"; do
	command -v "$tool" >/dev/null || { echo "missing $tool"; exit 2; }
done
[ -x "$REMULE" ] || { echo "missing $REMULE (cargo build --release -p remule-cli)"; exit 2; }
case "$DIRECTION" in remule-asks | amule-asks) ;; *) echo "DIRECTION?"; exit 2 ;; esac

WORK=$(mktemp -d)
CFG="$WORK/amule"
mkdir -p "$CFG/Temp" "$CFG/Incoming" "$WORK/share"

PIDS=()
cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	sleep 1
	for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
	if [ "${KEEP:-0}" = "1" ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

cmd() { "$AMULECMD" -h 127.0.0.1 -p "$EC_PORT" -P "$EC_PASS" -c "$1" 2>&1; }

fail() {
	echo "FAIL: $*"
	for f in "$WORK"/asker.log "$WORK"/sharer.log; do
		[ -f "$f" ] || continue
		echo "----- $(basename "$f") (UDP, queue and connections) -----"
		grep -E "^udp|queue rank|logged in|accepted|connected|sending|slot|upload|dropped|closed" "$f" | head -60
	done
	for f in "$WORK"/filler*.log; do
		[ -f "$f" ] || continue
		echo "----- $(basename "$f") (tail) -----"
		grep -v '^[[:space:]]*$' "$f" | tail -6
	done
	echo "----- aMule -----"
	cmd status | tail -6
	cmd "show ul" | tail -8
	cmd "show dl" | tail -8
	grep -iv "External connection\|Connecting client: aMulecmd\|Access granted\|New external" \
		"$CFG/logfile" 2>/dev/null | tail -30
	echo "----- server -----"
	tail -30 "$WORK/server.log"
	exit 1
}

# The address of the default route (a UDP connect sends nothing).
IP=$(python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("10.255.255.255", 1))
print(s.getsockname()[0])' 2>/dev/null)
case "$IP" in
"" | 127.*) echo "no address but loopback"; exit 2 ;;
esac
echo "this machine: $IP, $DIRECTION"

python3 "$HERE/fake_ed2k_server.py" "$IP" "$SERVER_PORT" >"$WORK/server.log" 2>&1 &
PIDS+=($!)

# The shared file, and its link with the uploader as its source.
NAME="udp-reask.bin"
head -c "$SIZE" /dev/urandom >"$WORK/share/$NAME"
BARE=$("$REMULE" hash "$WORK/share/$NAME" | grep -m1 '^ed2k://')
if [ "$DIRECTION" = remule-asks ]; then
	cp "$WORK/share/$NAME" "$CFG/Incoming/"
	UP_ADDR="$IP:$AMULE_TCP"
	UP_UDP="$IP:$AMULE_UDP"
	AMULE_MAX_UPLOAD=1
else
	UP_ADDR="$IP:4700"
	UP_UDP="$IP:4710"
	AMULE_MAX_UPLOAD=0
fi
LINK="${BARE}|sources,$UP_ADDR|/"
echo "link: $LINK"

# A stock aMule: eD2k only, its UDP port open, obfuscation supported and
# requested; its one server the fake one.
cat >"$CFG/amule.conf" <<EOF
[eMule]
Nick=amule-udp
Port=$AMULE_TCP
UDPPort=$AMULE_UDP
UDPDisable=0
TempDir=$CFG/Temp
IncomingDir=$CFG/Incoming
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
MaxUpload=$AMULE_MAX_UPLOAD
SourceReaskMinutes=2
[Obfuscation]
IsClientCryptLayerSupported=1
IsCryptLayerRequested=1
IsClientCryptLayerRequired=0
[ExternalConnect]
AcceptExternalConnections=1
ECAddress=127.0.0.1
ECPort=$EC_PORT
ECPassword=$(printf '%s' "$EC_PASS" | md5sum | cut -d' ' -f1)
IpFilterClients=0
IpFilterServers=0
EOF
python3 - "$IP" "$SERVER_PORT" "$CFG/server.met" <<'PY'
import socket, struct, sys
ip, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
# MET_HEADER, one server, no tags.
open(path, "wb").write(struct.pack("<BI", 0x0E, 1) + socket.inet_aton(ip) + struct.pack("<HI", port, 0))
PY
: >"$CFG/addresses.dat"
"$AMULED" --config-dir="$CFG" >"$WORK/amuled.log" 2>&1 &
PIDS+=($!)
up=0
for _ in $(seq 1 60); do
	cmd status | grep -q "Succeeded" && { up=1; break; }
	sleep 1
done
[ "$up" = 1 ] || fail "amuled did not come up"
"$AMULED" --version 2>/dev/null | sed -n 1p || true
cmd "connect $IP:$SERVER_PORT" >/dev/null
for _ in $(seq 1 30); do
	cmd status | grep -qi "ed2k: connected" && break
	sleep 1
done
cmd status | grep -i "ed2k" || true

# A remule downloader: N, its ports 470N / 471N, more arguments after.
downloader() {
	local n=$1
	shift
	"$REMULE" download "$LINK" --server "$IP:$SERVER_PORT" --allow-lan \
		--config "$WORK/c$n" --temp "$WORK/t$n" --incoming "$WORK/i$n" \
		--port "470$n" --udp-port "471$n" --status-every 15 "$@"
}

if [ "$DIRECTION" = remule-asks ]; then
	for _ in $(seq 1 60); do
		cmd "show shared" | grep -q "$NAME" && break
		sleep 1
	done
	cmd "show shared" | grep -q "$NAME" || fail "aMule did not share the file"
	# Two take aMule's two slots, slowly (1 KiB/s between them).
	for n in 1 2; do
		downloader "$n" --duration 400 >"$WORK/filler$n.log" 2>&1 &
		PIDS+=($!)
		sleep 3
	done
	sleep 5
	# The asker: queued, it asks over UDP at 100 s and again at 200 s.
	REMULE_TRACE=1 downloader 3 --reask 120 --duration 230 >"$WORK/asker.log" 2>&1
	T="$WORK/asker.log"
	echo "----- remule's datagrams with aMule -----"
	grep "^udp" "$T" | sort | uniq -c
	grep "queue rank" "$T" | head -5
	grep -qF "] $UP_ADDR: queue rank" "$T" || fail "remule was not queued by aMule"
	grep -q "^udp -> $UP_UDP ReaskFilePing obfuscated" "$T" || fail "remule sent aMule no obfuscated UDP reask"
	grep -q "^udp -> $UP_UDP ReaskFilePing plain" "$T" && fail "remule sent aMule a plain UDP reask"
	grep -q "^udp <- $UP_UDP ReaskAck obfuscated" "$T" || fail "aMule did not answer the UDP reask (obfuscated)"
	echo "PASS: remule, queued by a stock aMule, asked again over UDP and got its rank, obfuscated both ways"
else
	# remule shares at 2 KiB/s: two slots. Four remules come first: two
	# take the slots, two wait ahead of aMule, so a filler that drops its
	# slot does not hand it to aMule (the longest waiting gets it).
	REMULE_TRACE=1 "$REMULE" download --share "$WORK/share" --server "$IP:$SERVER_PORT" --allow-lan \
		--config "$WORK/c0" --temp "$WORK/t0" --incoming "$WORK/i0" \
		--port 4700 --udp-port 4710 --max-upload 2 --duration 300 --status-every 30 \
		>"$WORK/sharer.log" 2>&1 &
	PIDS+=($!)
	sleep 5
	for n in 1 2 3 4; do
		downloader "$n" --duration 300 >"$WORK/filler$n.log" 2>&1 &
		PIDS+=($!)
		sleep 3
	done
	sleep 5
	cmd "add $LINK"
	T="$WORK/sharer.log"
	A="$IP:$AMULE_UDP"
	# aMule asks over UDP after 2 minutes less 20 s.
	start=$(date +%s)
	until grep -q "^udp -> $A ReaskAck" "$T"; do
		[ $(($(date +%s) - start)) -gt 240 ] && break
		sleep 10
	done
	echo "waited $(($(date +%s) - start)) s"
	echo "----- remule's datagrams with aMule -----"
	grep "^udp" "$T" | grep -F " $A " | sort | uniq -c
	grep -q "^udp <- $A ReaskFilePing obfuscated" "$T" || fail "aMule sent remule no obfuscated UDP reask"
	grep -q "^udp <- $A ReaskFilePing plain" "$T" && fail "aMule sent remule a plain UDP reask"
	grep -q "^udp -> $A ReaskAck obfuscated" "$T" || fail "remule did not answer aMule's UDP reask with its rank (obfuscated)"
	echo "PASS: a stock aMule, queued by remule, asked again over UDP and got its rank, obfuscated both ways"
fi
