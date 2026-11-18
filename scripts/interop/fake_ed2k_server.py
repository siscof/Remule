#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""A scripted eD2k server, just enough for an aMule to log in.

Stock aMule 2.3.3 asks its sources only while it is connected to eD2k or
Kad (`CPartFile::Process`, `theApp->IsConnected()`). This accepts the login
(`OP_LOGINREQUEST`) and answers with a message, a status and `OP_IDCHANGE`
giving the client a HighID: its own address. Every search
(`OP_SEARCHREQUEST`) is answered with the one file in `SEARCH_RESULT`.
Everything else is read and ignored; no sources.

Usage: fake_ed2k_server.py LISTEN_IP PORT
"""

import socket
import struct
import sys
import threading

OP_EDONKEYPROT = 0xE3
OP_LOGINREQUEST = 0x01
OP_SERVERMESSAGE = 0x38
OP_SERVERSTATUS = 0x34
OP_IDCHANGE = 0x40
OP_SEARCHREQUEST = 0x16
OP_SEARCHRESULT = 0x33
# Old-style tags: type, a one-byte name, the value.
TAGTYPE_STRING = 0x02
TAGTYPE_UINT32 = 0x03
FT_FILENAME = 0x01
FT_FILESIZE = 0x02
FT_SOURCES = 0x15
# (hash, name, size) of the file every search finds.
SEARCH_RESULT = (bytes([0x5E] * 16), "remule interop result.iso", 7_340_032)
# SRV_TCPFLG_COMPRESSION | SRV_TCPFLG_NEWTAGS | SRV_TCPFLG_UNICODE | SRV_TCPFLG_LARGEFILES
TCP_FLAGS = 0x0001 | 0x0008 | 0x0010 | 0x0100


def packet(opcode, payload=b""):
    return struct.pack("<BIB", OP_EDONKEYPROT, len(payload) + 1, opcode) + payload


def tag(tagtype, name, value):
    head = struct.pack("<BHB", tagtype, 1, name)
    if tagtype == TAGTYPE_STRING:
        raw = value.encode()
        return head + struct.pack("<H", len(raw)) + raw
    return head + struct.pack("<I", value)


def search_result():
    h, name, size = SEARCH_RESULT
    tags = [
        tag(TAGTYPE_STRING, FT_FILENAME, name),
        tag(TAGTYPE_UINT32, FT_FILESIZE, size),
        tag(TAGTYPE_UINT32, FT_SOURCES, 3),
    ]
    # One file: hash, a source's ID and port, its tags; then "no more".
    entry = h + struct.pack("<IHI", 0x0100007F, 4662, len(tags)) + b"".join(tags)
    return packet(OP_SEARCHRESULT, struct.pack("<I", 1) + entry + b"\x00")


def read_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def serve(conn, addr):
    print(f"client {addr[0]}:{addr[1]} connected", flush=True)
    try:
        while True:
            head = read_exact(conn, 5)
            if head is None:
                break
            proto, size = struct.unpack("<BI", head)
            body = read_exact(conn, size)
            if body is None or size == 0:
                break
            opcode = body[0]
            print(f"  <- {proto:#04x}/{opcode:#04x} {size - 1} bytes", flush=True)
            if proto == OP_EDONKEYPROT and opcode == OP_LOGINREQUEST:
                msg = b"remule interop test server"
                conn.sendall(packet(OP_SERVERMESSAGE, struct.pack("<H", len(msg)) + msg))
                conn.sendall(packet(OP_SERVERSTATUS, struct.pack("<II", 1, 0)))
                # The client's own address as its ID: first octet in the low byte.
                conn.sendall(packet(OP_IDCHANGE, socket.inet_aton(addr[0]) + struct.pack("<I", TCP_FLAGS)))
                print(f"  -> HighID {addr[0]}", flush=True)
            elif proto == OP_EDONKEYPROT and opcode == OP_SEARCHREQUEST:
                conn.sendall(search_result())
                print("  -> 1 search result", flush=True)
    except OSError as e:
        print(f"  {e}", flush=True)
    finally:
        conn.close()
        print(f"client {addr[0]}:{addr[1]} gone", flush=True)


def main():
    ip, port = sys.argv[1], int(sys.argv[2])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(4)
    print(f"listening on {ip}:{port}", flush=True)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=serve, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
