#!/usr/bin/env python3
"""Decode a usbmon pcap (LINKTYPE_USB_LINUX_MMAPPED=220 or 189) and print
bulk/control transfers for one device as hex, one line per packet.
usage: usbpcap.py file.pcap [devnum] [--all]"""
import struct, sys
f = open(sys.argv[1], "rb"); hdr = f.read(24)
magic = hdr[:4]
if magic == b"\xd4\xc3\xb2\xa1": end = "<"
elif magic == b"\xa1\xb2\xc3\xd4": end = ">"
else: sys.exit("not a pcap (pcapng? use -F pcap in tcpdump)")
linktype = struct.unpack(end + "I", hdr[20:24])[0]
want = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else None
showall = "--all" in sys.argv
n = 0
while True:
    ph = f.read(16)
    if len(ph) < 16: break
    ts_sec, ts_usec, incl, orig = struct.unpack(end + "IIII", ph)
    pkt = f.read(incl)
    if len(pkt) < 48: continue
    (urb_id, ev, xfer, epnum, devnum, busnum, flag_setup, flag_data, ts_s, ts_u,
     status, length, len_cap) = struct.unpack("<QBBBBHBBqiiII", pkt[:40])
    setup = pkt[40:48]
    if linktype == 220: data = pkt[64:64 + len_cap]
    else: data = pkt[48:48 + len_cap]
    if want is not None and devnum != want: continue
    if not showall and len(data) == 0 and not (flag_setup == 0): continue
    d = {0: "ISO", 1: "INT", 2: "CTRL", 3: "BULK"}.get(xfer, str(xfer))
    dirn = "IN " if epnum & 0x80 else "OUT"
    n += 1
    t = ts_sec + ts_usec / 1e6
    s = f"{t:14.6f} {chr(ev)} {d:4} {dirn} ep{epnum & 0xf} len={length:4d}"
    if flag_setup == 0: s += " setup=" + setup.hex()
    if data: s += " " + data.hex(" ")
    print(s)
