#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""A scripted eD2k server, just enough for an aMule to log in.

Stock aMule 2.3.3 asks its sources only while it is connected to eD2k or
Kad (`CPartFile::Process`, `theApp->IsConnected()`). This accepts the login
(`OP_LOGINREQUEST`) and answers with a message, a status and `OP_IDCHANGE`
giving the client a HighID: its own address. Every search
(`OP_SEARCHREQUEST`) is answered with the one file in `SEARCH_RESULT`.
A source request (`OP_GETSOURCES`, `OP_GETSOURCES_OBFU`) is answered with
the other clients logged in that offered the file (`OP_OFFERFILES`, packed
or not): their HighID and port, and for `_OBFU` the obfuscation settings
and user hash of their login (`OP_FOUNDSOURCES_OBFU`). Everything else is
read and ignored.

Usage: fake_ed2k_server.py LISTEN_IP PORT
"""

import socket
import struct
import sys
import threading
import zlib

OP_EDONKEYPROT = 0xE3
OP_PACKEDPROT = 0xD4
OP_OFFERFILES = 0x15
OP_GETSOURCES = 0x19
OP_GETSOURCES_OBFU = 0x23
OP_FOUNDSOURCES = 0x42
OP_FOUNDSOURCES_OBFU = 0x44
CT_SERVER_FLAGS = 0x20
# SRVCAP_SUPPORTCRYPT, _REQUESTCRYPT, _REQUIRECRYPT: bits 0, 1 and 2 of a
# source's obfuscation settings.
SRVCAP_CRYPT = ((0x0200, 0x01), (0x0400, 0x02), (0x0800, 0x04))
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
# SRV_TCPFLG_COMPRESSION | SRV_TCPFLG_NEWTAGS | SRV_TCPFLG_UNICODE |
# SRV_TCPFLG_LARGEFILES | SRV_TCPFLG_TCPOBFUSCATION (asks for _OBFU sources)
TCP_FLAGS = 0x0001 | 0x0008 | 0x0010 | 0x0100 | 0x0400

# Who is logged in: conn -> {"id", "port", "hash", "crypt", "offered"}.
CLIENTS = {}
LOCK = threading.Lock()


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


# Sizes of the fixed-size tag types (TAGTYPE_*).
TAG_FIXED = {0x01: 16, 0x03: 4, 0x04: 4, 0x05: 1, 0x08: 2, 0x09: 1, 0x0B: 8}


def read_tags(data, pos, count):
    """Tags old or new style, as {name: value}: integers and strings kept,
    the rest skipped. Returns (tags, the position after them)."""
    tags = {}
    for _ in range(count):
        ttype = data[pos]
        pos += 1
        if ttype & 0x80:
            ttype &= 0x7F
            name = data[pos]
            pos += 1
        else:
            (nlen,) = struct.unpack_from("<H", data, pos)
            pos += 2
            name = data[pos] if nlen == 1 else data[pos:pos + nlen]
            pos += nlen
        if ttype in (0x03, 0x08, 0x09, 0x0B):
            size = TAG_FIXED[ttype]
            tags[name] = int.from_bytes(data[pos:pos + size], "little")
            pos += size
        elif ttype in TAG_FIXED:
            pos += TAG_FIXED[ttype]
        elif ttype == 0x02:
            (slen,) = struct.unpack_from("<H", data, pos)
            tags[name] = data[pos + 2:pos + 2 + slen].decode("utf-8", "replace")
            pos += 2 + slen
        elif 0x11 <= ttype <= 0x20:
            slen = ttype - 0x10
            tags[name] = data[pos:pos + slen].decode("utf-8", "replace")
            pos += slen
        elif ttype == 0x06:
            (bits,) = struct.unpack_from("<H", data, pos)
            pos += 2 + (bits + 7) // 8
        elif ttype == 0x07:
            (blen,) = struct.unpack_from("<I", data, pos)
            pos += 4 + blen
        elif ttype == 0x0A:
            pos += 1 + data[pos]
        else:
            raise ValueError(f"tag type {ttype:#04x}")
    return tags, pos


def login(conn, addr, body):
    """OP_LOGINREQUEST: <hash 16><id 4><port 2><tag count 4><tags>."""
    user_hash = body[1:17]
    (port,) = struct.unpack_from("<H", body, 21)
    (count,) = struct.unpack_from("<I", body, 23)
    try:
        tags, _ = read_tags(body, 27, count)
    except (ValueError, IndexError, struct.error) as e:
        # The login is answered all the same; only the flags are lost.
        print(f"  login tags: {e}", flush=True)
        tags = {}
    flags = tags.get(CT_SERVER_FLAGS, 0)
    crypt = 0
    for cap, bit in SRVCAP_CRYPT:
        if flags & cap:
            crypt |= bit
    with LOCK:
        CLIENTS[conn] = {
            "id": socket.inet_aton(addr[0]),
            "port": port,
            "hash": user_hash,
            "crypt": crypt,
            "offered": set(),
        }
    print(f"  login: {user_hash.hex()} port {port} flags {flags:#x}", flush=True)


def offer_files(conn, body):
    """OP_OFFERFILES: <count 4>(<hash 16><id 4><port 2><tag count 4><tags>)[count]."""
    (count,) = struct.unpack_from("<I", body, 1)
    pos = 5
    hashes = []
    for _ in range(count):
        hashes.append(body[pos:pos + 16])
        (ntags,) = struct.unpack_from("<I", body, pos + 22)
        _, pos = read_tags(body, pos + 26, ntags)
    with LOCK:
        if conn in CLIENTS:
            CLIENTS[conn]["offered"].update(hashes)
    print(f"  offered {count} files: {' '.join(h.hex() for h in hashes)}", flush=True)


def found_sources(conn, body, obfu):
    """OP_FOUNDSOURCES(_OBFU): <hash 16><count 1>(<id 4><port 2>[<crypt 1><hash 16>])[count]."""
    file_hash = body[1:17]
    with LOCK:
        others = [c for k, c in CLIENTS.items() if k is not conn and file_hash in c["offered"]]
    others = others[:255]
    entries = b""
    for c in others:
        entries += c["id"] + struct.pack("<H", c["port"])
        if obfu:
            # Bit 7: the user hash follows.
            entries += bytes([c["crypt"] | 0x80]) + c["hash"]
    opcode = OP_FOUNDSOURCES_OBFU if obfu else OP_FOUNDSOURCES
    conn.sendall(packet(opcode, file_hash + bytes([len(others)]) + entries))
    print(f"  -> {len(others)} sources of {file_hash.hex()}", flush=True)


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
            if proto == OP_PACKEDPROT:
                body = bytes([opcode]) + zlib.decompress(body[1:])
                proto = OP_EDONKEYPROT
            if proto == OP_EDONKEYPROT and opcode == OP_LOGINREQUEST:
                login(conn, addr, body)
                msg = b"remule interop test server"
                conn.sendall(packet(OP_SERVERMESSAGE, struct.pack("<H", len(msg)) + msg))
                conn.sendall(packet(OP_SERVERSTATUS, struct.pack("<II", 1, 0)))
                # The client's own address as its ID: first octet in the low byte.
                conn.sendall(packet(OP_IDCHANGE, socket.inet_aton(addr[0]) + struct.pack("<I", TCP_FLAGS)))
                print(f"  -> HighID {addr[0]}", flush=True)
            elif proto == OP_EDONKEYPROT and opcode == OP_SEARCHREQUEST:
                conn.sendall(search_result())
                print("  -> 1 search result", flush=True)
            elif proto == OP_EDONKEYPROT and opcode == OP_OFFERFILES:
                offer_files(conn, body)
            elif proto == OP_EDONKEYPROT and opcode in (OP_GETSOURCES, OP_GETSOURCES_OBFU):
                found_sources(conn, body, opcode == OP_GETSOURCES_OBFU)
    except (OSError, ValueError, IndexError, struct.error, zlib.error) as e:
        print(f"  {e}", flush=True)
    finally:
        with LOCK:
            CLIENTS.pop(conn, None)
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
