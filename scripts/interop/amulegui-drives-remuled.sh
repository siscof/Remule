#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MIGRATION_PLAN.md 11.M: the unmodified C++ amulegui drives remuled.
#
# remuled runs from an aMule config directory with External Connections
# on. amulegui, built from the aMule-org source remule is ported from,
# starts with a saved connection (remote.conf, --skip: no dialog) and an
# ed2k link on its command line. It hands links to the core only once its
# connect sequence is done (the preferences read, EC_OP_GET_PREFERENCES;
# then OnECInitDone), so the link showing up in remuled's download queue
# means amulegui got through it. It is then left polling (EC_OP_STAT_REQ
# and EC_OP_GET_UPDATE, incremental) for a while, and must still be
# connected and running. amulecmd checks the queue. Needs an X display
# (xvfb-run in CI).
#
# Usage: xvfb-run -a scripts/interop/amulegui-drives-remuled.sh
# Environment:
#   REMULED=target/release/remuled   the daemon
#   AMULEGUI=amulegui                aMule's remote GUI
#   AMULECMD=amulecmd                aMule's command-line client
#   POLL=20                          seconds amulegui is left polling
#   KEEP=1                           keep the work directory

set -euo pipefail

REMULED=$(realpath "${REMULED:-target/release/remuled}")
AMULEGUI=${AMULEGUI:-amulegui}
AMULECMD=${AMULECMD:-amulecmd}
POLL=${POLL:-20}
EC_PORT=4712
EC_PASS=interop

command -v "$AMULEGUI" >/dev/null || { echo "missing $AMULEGUI"; exit 2; }
command -v "$AMULECMD" >/dev/null || { echo "missing $AMULECMD"; exit 2; }
[ -x "$REMULED" ] || { echo "missing $REMULED (cargo build --release -p remuled)"; exit 2; }
[ -n "${DISPLAY:-}" ] || { echo "no DISPLAY (run under xvfb-run)"; exit 2; }

WORK=$(mktemp -d)
CFG="$WORK/amule"
GUICFG="$WORK/gui"
mkdir -p "$CFG" "$GUICFG"

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
	echo "----- amulegui output -----"
	cat "$WORK/gui.log" || true
}

fail() {
	echo "FAIL: $*"
	dump_logs
	exit 1
}

cmd() {
	"$AMULECMD" -h 127.0.0.1 -p "$EC_PORT" -P "$EC_PASS" -c "$*" 2>&1 || true
}

EC_DIGEST=$(printf '%s' "$EC_PASS" | md5sum | cut -d' ' -f1)
cat >"$CFG/amule.conf" <<EOF
[eMule]
Nick=remuled-gui-interop
Port=4662
ConnectToKad=0
ConnectToED2K=0
[ExternalConnect]
AcceptExternalConnections=1
ECAddress=127.0.0.1
ECPort=$EC_PORT
ECPassword=$EC_DIGEST
EOF
# amulegui's saved connection, as its dialog writes it.
cat >"$GUICFG/remote.conf" <<EOF
[EC]
Host=127.0.0.1
Port=$EC_PORT
Password=$EC_DIGEST
EOF

"$REMULED" --config-dir "$CFG" >"$WORK/remuled.log" 2>&1 &
REMULED_PID=$!
PIDS+=($REMULED_PID)
for _ in $(seq 60); do
	grep -q "TCP socket (ECServer) listening" "$WORK/remuled.log" && break
	kill -0 "$REMULED_PID" 2>/dev/null || fail "remuled exited"
	sleep 1
done
grep -q "TCP socket (ECServer) listening" "$WORK/remuled.log" || fail "remuled never listened for EC"

HASH=FEDCBA9876543210FEDCBA9876543210
"$AMULEGUI" --config-dir="$GUICFG/" --skip --log-stdout \
	"ed2k://|file|gui%20link.iso|987654321|$HASH|/" >"$WORK/gui.log" 2>&1 &
GUI_PID=$!
PIDS+=($GUI_PID)

# Its connect sequence done: the link it was given is in the queue.
for _ in $(seq 90); do
	cmd "show dl" | grep -q "gui link\.iso" && break
	kill -0 "$GUI_PID" 2>/dev/null || fail "amulegui exited"
	sleep 1
done
cmd "show dl" | grep -q "gui link\.iso" || fail "amulegui never added its link"
echo "ok: amulegui connected, read the preferences and added its link"
grep -q "Connecting client: amule-remote" "$WORK/remuled.log" || fail "no amulegui login in the log"

# Left polling: it must stay up and connected.
sleep "$POLL"
kill -0 "$GUI_PID" 2>/dev/null || fail "amulegui exited while polling"
grep -qi "connection failed\|connection lost\|reconnect" "$WORK/gui.log" &&
	fail "amulegui lost the connection"
# What it asked that remuled does not answer yet, for the record; the
# requests it polls with must not be among them.
echo "----- requests remuled does not serve yet -----"
grep -o "invalid opcode received: 0x[0-9a-f]*" "$WORK/remuled.log" | sort | uniq -c || true
for op in 0x0a 0x3f 0x52; do
	grep -q "invalid opcode received: $op\$" "$WORK/remuled.log" &&
		fail "remuled did not answer opcode $op"
done
echo "ok: amulegui polled for $POLL s and stayed connected"

kill "$GUI_PID"
cmd shutdown >/dev/null
for _ in $(seq 30); do
	kill -0 "$REMULED_PID" 2>/dev/null || break
	sleep 1
done
kill -0 "$REMULED_PID" 2>/dev/null && fail "remuled did not stop on shutdown"
echo "----- amulegui output (tail) -----"
tail -30 "$WORK/gui.log"
echo "PASS: amulegui drove remuled"
