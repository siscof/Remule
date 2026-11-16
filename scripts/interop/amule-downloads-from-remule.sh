#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 9.M: a stock aMule downloads a file from remule.
#
# remule shares a random multi-part file; a stock amuled (the distribution's
# package, driven with amulecmd) is given its ed2k link with remule as the one
# source, and must finish it byte for byte. Neither side touches a server or
# Kad. aMule rejects loopback sources outright (IsGoodIP), so remule is
# reached on this machine's own LAN address, with FilterLanIPs off.
#
# Usage: scripts/interop/amule-downloads-from-remule.sh
# Environment:
#   REMULE=target/release/remule   the remule binary
#   SIZE=24000000                  bytes to share (default: three parts)
#   TIMEOUT=300                    seconds aMule gets to finish
#   KEEP=1                         keep the work directory

set -euo pipefail

REMULE=$(realpath "${REMULE:-target/release/remule}")
SIZE=${SIZE:-24000000}
TIMEOUT=${TIMEOUT:-300}
REMULE_PORT=4663
AMULE_PORT=4662
EC_PORT=4712
EC_PASS=interop

for tool in amuled amulecmd; do
	command -v "$tool" >/dev/null || { echo "missing $tool (install amule-daemon, amule-utils)"; exit 2; }
done
[ -x "$REMULE" ] || { echo "missing $REMULE (cargo build --release -p remule-cli)"; exit 2; }

WORK=$(mktemp -d)
AMULE_CFG="$WORK/amule"
mkdir -p "$WORK/share" "$AMULE_CFG/Temp" "$AMULE_CFG/Incoming"

PIDS=()
cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	if [ "${KEEP:-0}" = "1" ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

dump_logs() {
	echo "----- remule log -----"
	cat "$WORK/remule.log" || true
	echo "----- amuled output -----"
	cat "$WORK/amuled.log" || true
	echo "----- aMule logfile -----"
	cat "$AMULE_CFG/logfile" 2>/dev/null || true
	echo "----- aMule temp dir -----"
	ls -la "$AMULE_CFG/Temp" || true
}

IP=$(hostname -I | awk '{print $1}')
[ -n "$IP" ] || { echo "no LAN address"; exit 2; }
echo "this machine: $IP"

# The file, and its link with remule as the source.
NAME="remule-interop.bin"
head -c "$SIZE" /dev/urandom > "$WORK/share/$NAME"
LINK=$("$REMULE" hash "$WORK/share/$NAME" | grep -m1 '^ed2k://')
LINK="${LINK}|sources,$IP:$REMULE_PORT|/"
echo "link: $LINK"

# remule shares it and waits.
"$REMULE" download --share "$WORK/share" --config "$WORK/remule-config" \
	--temp "$WORK/remule-temp" --incoming "$WORK/remule-incoming" \
	--port "$REMULE_PORT" --allow-lan --duration $((TIMEOUT + 60)) --status-every 15 \
	> "$WORK/remule.log" 2>&1 &
PIDS+=($!)

# A stock aMule, offline: no server, no Kad, no IP filter, LAN sources allowed.
cat > "$AMULE_CFG/amule.conf" <<EOF
[eMule]
Nick=interop
Port=$AMULE_PORT
UDPPort=4672
UDPDisable=1
TempDir=$AMULE_CFG/Temp
IncomingDir=$AMULE_CFG/Incoming
FilterLanIPs=0
ConnectToKad=0
ConnectToED2K=0
Autoconnect=0
Reconnect=0
IPFilterAutoLoad=0
UPnPEnabled=0
[ExternalConnect]
AcceptExternalConnections=1
ECAddress=127.0.0.1
ECPort=$EC_PORT
ECPassword=$(printf '%s' "$EC_PASS" | md5sum | cut -d' ' -f1)
IpFilterClients=0
IpFilterServers=0
EOF
amuled --config-dir="$AMULE_CFG" > "$WORK/amuled.log" 2>&1 &
PIDS+=($!)

cmd() { amulecmd -h 127.0.0.1 -p "$EC_PORT" -P "$EC_PASS" -c "$1" 2>&1; }

up=0
for _ in $(seq 1 60); do
	if cmd status | grep -q "Succeeded"; then up=1; break; fi
	sleep 1
done
[ "$up" = 1 ] || { echo "amuled did not come up"; dump_logs; exit 1; }
amuled --version 2>/dev/null | head -1 || true
cmd status

echo "adding the link to aMule"
cmd "add $LINK"

start=$(date +%s)
while :; do
	now=$(date +%s)
	if [ -f "$AMULE_CFG/Incoming/$NAME" ] && cmp -s "$AMULE_CFG/Incoming/$NAME" "$WORK/share/$NAME"; then
		echo "aMule finished the file after $((now - start))s, byte for byte"
		grep -i "uploading" "$WORK/remule.log" || true
		exit 0
	fi
	if [ $((now - start)) -ge "$TIMEOUT" ]; then
		echo "aMule did not finish in ${TIMEOUT}s"
		cmd "show dl" || true
		dump_logs
		exit 1
	fi
	if [ $(((now - start) % 15)) -eq 0 ]; then
		cmd "show dl" | grep -i "$NAME" || true
	fi
	sleep 1
done
