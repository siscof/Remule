#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 4.M and 8.M: remule downloads a file from a stock aMule,
# obfuscated.
#
# A released amuled (upstream's static build) shares a random multi-part
# file and requires obfuscation of every peer (IsClientCryptLayerRequired:
# a plain connection is refused). Both log into fake_ed2k_server.py, aMule
# first: aMule offers the file (OP_OFFERFILES), remule asks for its sources
# (OP_GETSOURCES_OBFU) and is given aMule with its user hash and its
# obfuscation settings (OP_FOUNDSOURCES_OBFU), as a real server gives them.
# remule must connect to aMule with the obfuscated handshake (client to
# client, keyed on aMule's user hash) and finish the file byte for byte.
# Nothing touches the real network. aMule drops loopback servers and
# sources (IsGoodIP), so everything runs on this machine's own address,
# with FilterLanIPs off.
#
# Usage: scripts/interop/remule-downloads-from-amule.sh
# Environment:
#   REMULE=target/release/remule   the remule binary
#   SIZE=24000000                  bytes to share (default: three parts)
#   TIMEOUT=180                    seconds remule gets to finish
#   KEEP=1                         keep the work directory

set -uo pipefail

REMULE=$(realpath "${REMULE:-target/release/remule}")
SIZE=${SIZE:-24000000}
TIMEOUT=${TIMEOUT:-180}
AMULE_PORT=4662
REMULE_PORT=4663
# Not 4661: see amule-downloads-from-remule.sh.
SERVER_PORT=4242
HERE=$(dirname "$(realpath "$0")")
EC_PORT=4712
EC_PASS=interop

for tool in amuled amulecmd; do
	command -v "$tool" >/dev/null || { echo "missing $tool (aMule's release tarball)"; exit 2; }
done
[ -x "$REMULE" ] || { echo "missing $REMULE (cargo build --release -p remule-cli)"; exit 2; }

WORK=$(mktemp -d)
CFG="$WORK/amule"
mkdir -p "$CFG/Temp" "$CFG/Incoming"

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
	echo "----- remule (tail) -----"
	tail -80 "$WORK/remule.log" 2>/dev/null || true
	echo "----- aMule logfile -----"
	grep -v "External connection\|Connecting client: aMulecmd\|Access granted\|New external" \
		"$CFG/logfile" 2>/dev/null || true
	echo "----- remule's temp dir -----"
	ls -la "$WORK/remule-temp" 2>/dev/null || true
	exit 1
}

cmd() { amulecmd -h 127.0.0.1 -p "$EC_PORT" -P "$EC_PASS" -c "$1" 2>&1; }

# The address of the default route (a UDP connect sends nothing).
IP=$(python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("10.255.255.255", 1))
print(s.getsockname()[0])' 2>/dev/null)
case "$IP" in
"" | 127.*) echo "no address but loopback"; exit 2 ;;
esac
echo "this machine: $IP"

# The file aMule shares, and its link: no source in it, the server gives it.
NAME="remule-from-amule.bin"
head -c "$SIZE" /dev/urandom >"$CFG/Incoming/$NAME"
HASH_OUT=$("$REMULE" hash "$CFG/Incoming/$NAME")
LINK=$(printf '%s\n' "$HASH_OUT" | grep -m1 '^ed2k://')
HASH=$(printf '%s\n' "$LINK" | cut -d'|' -f5 | tr 'A-F' 'a-f')
echo "link: $LINK"

python3 "$HERE/fake_ed2k_server.py" "$IP" "$SERVER_PORT" >"$WORK/server.log" 2>&1 &
PIDS+=($!)

# A stock aMule, obfuscation required, its one server the fake one.
cat >"$CFG/amule.conf" <<EOF
[eMule]
Nick=amule-source
Port=$AMULE_PORT
UDPPort=4672
UDPDisable=1
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
MaxUpload=0
[Obfuscation]
IsClientCryptLayerSupported=1
IsCryptLayerRequested=1
IsClientCryptLayerRequired=1
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
amuled --config-dir="$CFG" >"$WORK/amuled.log" 2>&1 &
PIDS+=($!)

up=0
for _ in $(seq 1 60); do
	cmd status | grep "Succeeded" >/dev/null && { up=1; break; }
	sleep 1
done
[ "$up" = 1 ] || fail "amuled did not come up"
amuled --version 2>/dev/null | sed -n 1p || true

# Hashed before it is offered: wait for it in the shared files.
for _ in $(seq 1 60); do
	cmd "show shared" | grep "$NAME" >/dev/null && break
	sleep 1
done
cmd "show shared" | grep "$NAME" >/dev/null || fail "aMule did not share the file"

cmd "connect $IP:$SERVER_PORT" >/dev/null
offered=0
for _ in $(seq 1 60); do
	grep -qs "offered .*$HASH" "$WORK/server.log" && { offered=1; break; }
	sleep 1
done
[ "$offered" = 1 ] || fail "aMule did not offer the file to the server"
grep -s "login:" "$WORK/server.log" | sed -n 1p
echo "aMule offered the file to the server"

# remule: the link, the server; every peer connection traced.
start=$(date +%s)
REMULE_TRACE=1 "$REMULE" download "$LINK" --server "$IP:$SERVER_PORT" \
	--temp "$WORK/remule-temp" --incoming "$WORK/remule-incoming" --config "$WORK/remule-config" \
	--port "$REMULE_PORT" --allow-lan --duration "$TIMEOUT" --status-every 15 \
	>"$WORK/remule.log" 2>&1
status=$?
elapsed=$(($(date +%s) - start))
echo "remule exited with $status after ${elapsed}s"

grep -qs -- "-> 1 sources of $HASH" "$WORK/server.log" || fail "the server never gave remule aMule as a source"
grep -s "^$IP:$AMULE_PORT connected" "$WORK/remule.log" | sort | uniq -c
grep -qs "^$IP:$AMULE_PORT connected, plain" "$WORK/remule.log" && fail "remule connected to aMule unobfuscated"
grep -qs "^$IP:$AMULE_PORT connected, obfuscated" "$WORK/remule.log" || fail "remule never connected to aMule obfuscated"
[ -f "$WORK/remule-incoming/$NAME" ] || fail "remule did not finish the file in ${TIMEOUT}s"
cmp -s "$WORK/remule-incoming/$NAME" "$CFG/Incoming/$NAME" || fail "the file remule finished differs"
echo "PASS: remule downloaded $SIZE bytes from a stock aMule that requires obfuscation, in ${elapsed}s"
