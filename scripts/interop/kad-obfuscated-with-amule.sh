#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 4.M: UDP obfuscation against a stock aMule, on Kad.
#
# A released amuled (upstream's static build), Kad only, obfuscation
# supported, requested and required, and `remule kad` bootstrap from each
# other on this machine's own address (FilterLanIPs off on both sides).
# remule's bootstrap request goes out plain (it knows no key of aMule's
# yet, as aMule's own does); everything after it must be obfuscated both
# ways, and remule's trace (REMULE_TRACE) shows each datagram with its key:
#   - aMule answers remule's obfuscated requests (it decrypted them);
#   - aMule sends remule packets keyed on remule's Kad ID, which remule
#     decrypts and parses;
#   - aMule's packets carry the verify key remule gave it (receiver key
#     valid), so aMule read the sender key out of remule's packets;
#   - aMule's own requests (its ping, its firewall check) reach remule
#     obfuscated, and remule's answers go back obfuscated.
# Nothing touches the real network.
#
# Not checked: aMule searching remule. aMule's Kad never takes a LAN address
# into its routing table, whatever FilterLanIPs says (IsGoodIPPort is
# IsGoodIP(ip, true)), so on this machine's private address remule is never
# its contact: it answers remule but asks it nothing a search would.
#
# Usage: scripts/interop/kad-obfuscated-with-amule.sh
# Environment:
#   REMULE=target/release/remule   the remule binary
#   DURATION=120                   seconds remule's Kad node runs
#   KEEP=1                         keep the work directory

set -uo pipefail

REMULE=$(realpath "${REMULE:-target/release/remule}")
DURATION=${DURATION:-120}
AMULE_TCP=4662
AMULE_UDP=4672
REMULE_UDP=4673
EC_PORT=4712
EC_PASS=interop
WORD=remulekadcheck

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
	echo "----- remule (stdout) -----"
	cat "$WORK/remule.out" 2>/dev/null || true
	echo "----- remule's trace (head) -----"
	head -60 "$WORK/remule.trace" 2>/dev/null || true
	echo "----- aMule status -----"
	cmd status
	echo "----- aMule logfile -----"
	grep -v "External connection\|Connecting client: aMulecmd\|Access granted\|New external" \
		"$CFG/logfile" 2>/dev/null || true
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

# A stock aMule on Kad only; no nodes.dat, and nowhere to fetch one from.
cat >"$CFG/amule.conf" <<EOF
[eMule]
Nick=amule-kad
Port=$AMULE_TCP
UDPPort=$AMULE_UDP
UDPDisable=0
TempDir=$CFG/Temp
IncomingDir=$CFG/Incoming
FilterLanIPs=0
ConnectToKad=1
ConnectToED2K=0
Autoconnect=0
Reconnect=0
IPFilterAutoLoad=0
UPnPEnabled=0
GeoIPEnabled=0
GeoIPAutoUpdate=0
NewVersionCheck=0
KadNodesUrl=http://127.0.0.1:9/nodes.dat
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

cmd "connect kad" >/dev/null
for _ in $(seq 1 30); do
	cmd status | grep -i "kad" | grep -vqi "not running\|off" && break
	sleep 1
done
cmd status | grep -i "kad" || true

# remule: Kad from aMule alone, a keyword search of its own, every datagram
# traced. A contact from a bootstrap answer is not searched until a hello
# has verified it, which the small timer (once a minute) sends: the search
# waits 70 s.
T="$WORK/remule.trace"
A="$IP:$AMULE_UDP"
REMULE_TRACE=1 "$REMULE" kad --dir "$WORK/remule-kad" --port "$REMULE_UDP" \
	--bootstrap "$A" --allow-lan --reachable \
	--search "$WORD" --warmup 70 --duration "$DURATION" --status-every 15 \
	>"$WORK/remule.out" 2>"$T" &
RPID=$!
PIDS+=($RPID)
wait "$RPID"
echo "remule exited with $?"
cmd status | grep -i "kad" || true

echo "----- remule's datagrams with aMule, by kind -----"
grep -F " $A " "$T" | sort | uniq -c | sort -rn
tail -3 "$WORK/remule.out"

grep -qF "kad -> $A BootstrapReq" "$T" || fail "remule sent no bootstrap request"
grep -qF "kad <- $A " "$T" || fail "aMule never answered remule"
# After the bootstrap request (no key known), nothing to aMule is plain.
grep -F "kad -> $A " "$T" | grep -v " BootstrapReq " | grep -qF " plain" &&
	fail "remule sent aMule a plain packet once it knew its key"
grep -F "kad -> $A " "$T" | grep -qF " obfuscated" || fail "remule sent aMule nothing obfuscated"
# Answers to requests that went out obfuscated: aMule decrypted them.
for op in HelloRes Res; do
	grep -qE "kad <- $A $op obfuscated" "$T" || fail "no obfuscated $op from aMule"
done
grep -F "kad <- $A " "$T" | grep -v " BootstrapRes " | grep -qF " plain" &&
	fail "aMule sent remule a plain packet after the bootstrap"
grep -qE "kad <- $A [A-Za-z0-9]+ obfuscated \(Kad ID\)" "$T" ||
	fail "aMule never keyed a packet on remule's Kad ID"
grep -qF "receiver key valid" "$T" || fail "aMule never sent back the verify key remule gave it"
# aMule's own requests, and remule's answers to them.
grep -qE "kad <- $A (Ping|Firewalled2Req) obfuscated" "$T" ||
	fail "no request of aMule's own reached remule obfuscated"
grep -qE "kad -> $A Pong obfuscated" "$T" || fail "remule did not answer aMule's ping obfuscated"
grep -qE "kad -> $A SearchKeyReq obfuscated" "$T" || fail "remule's search did not reach aMule obfuscated"
echo "PASS: Kad with a stock aMule, obfuscated both ways after the bootstrap"
