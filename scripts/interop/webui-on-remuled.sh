#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 12.M: aMule's web UI works against remuled.
#
# remuled runs from an aMule config directory logged into a scripted ed2k
# server (fake_ed2k_server.py, which also answers searches), sharing one
# file; the unmodified C++ amuleapi serves aMule's static web UI in front of
# it. webui_check.js drives the UI in Chromium (Playwright): it signs in,
# opens every section, searches, adds a link, and looks at what each shows.
# A JavaScript error, a failed API call, or a section that does not show
# what remuled has fails the run. Screenshots are kept with KEEP=1.
#
# Usage: scripts/interop/webui-on-remuled.sh
# Environment:
#   REMULED=target/release/remuled   the daemon
#   AMULEAPI=amuleapi                aMule's REST API daemon
#   STATIC=.../src/webapi/static     aMule's web UI
#   KEEP=1                           keep the work directory (and screenshots)

set -uo pipefail

REMULED=$(realpath "${REMULED:-target/release/remuled}")
AMULEAPI=${AMULEAPI:-amuleapi}
STATIC=$(realpath "${STATIC:?set STATIC to aMule src/webapi/static}")
HERE=$(dirname "$(realpath "$0")")
TCP_PORT=4662
SERVER_PORT=4242
EC_PORT=4712
API_PORT=4713
EC_PASS=webui
ADMIN_PASS=adminpass

[ -x "$REMULED" ] || { echo "missing $REMULED (cargo build --release -p remuled)"; exit 2; }
command -v "$AMULEAPI" >/dev/null || { echo "missing $AMULEAPI"; exit 2; }
[ -f "$STATIC/index.html" ] || { echo "no index.html in $STATIC"; exit 2; }
node -e "require('playwright')" 2>/dev/null || { echo "node with playwright is needed"; exit 2; }

WORK=$(mktemp -d)
CFG="$WORK/amule"
API_CFG="$WORK/amuleapi"
mkdir -p "$CFG" "$API_CFG" "$WORK/share" "$WORK/shots"

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
	for f in remuled server amuleapi; do
		echo "----- $f log (tail) -----"
		tail -40 "$WORK/$f.log" 2>/dev/null || true
	done
	exit 1
}

# --- remuled, as in amulecmd-drives-remuled.sh -------------------------------

EC_DIGEST=$(printf '%s' "$EC_PASS" | md5sum | cut -d' ' -f1)
cat >"$CFG/amule.conf" <<EOF
[eMule]
Nick=remuled-webui
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
head -c 300000 /dev/urandom >"$WORK/share/webui shared file.bin"
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

# --- amuleapi with the web UI, as aMule's suite sets it up -------------------

"$AMULEAPI" --config-dir="$API_CFG" --set-admin-pass="$ADMIN_PASS" >/dev/null 2>&1
printf '%s\n' "$EC_PASS" | "$AMULEAPI" --config-dir="$API_CFG" --set-ec-pass-stdin >/dev/null 2>&1
sed -i "s|^StaticRoot=.*|StaticRoot=$STATIC|" "$API_CFG/amuleapi.conf"
"$AMULEAPI" --config-dir="$API_CFG" --host=127.0.0.1 --port="$EC_PORT" >"$WORK/amuleapi.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 30); do
	curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$API_PORT/api/v1/health" && break
	sleep 1
done
curl -s -o /dev/null "http://127.0.0.1:$API_PORT/api/v1/health" || fail "amuleapi never answered"

# --- the browser -------------------------------------------------------------

URL="http://127.0.0.1:$API_PORT/" PASS="$ADMIN_PASS" SHOTS="$WORK/shots" \
	node "$HERE/webui_check.js" || fail "the web UI check failed"
echo "PASS: aMule's web UI works against remuled"
