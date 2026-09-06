#!/usr/bin/env python3
"""
Low-level "type-nibble" transport for the UPEK 147e:2020 operation layer.

The device speaks TWO framings over the same bulk endpoints (0x02 OUT / 0x81 IN),
both prefixed with the ASCII magic "Ciao":

  1. The AES command channel (see upek2020.py): "Ciao"|seq|sub|b6=0x17|b7=0x28|
     len32|00 80|AES(cmd)|crc16 — carries info/config/enumerate commands.

  2. This low-level type-nibble transport — carries the capture/scan OPERATION:
        "Ciao" | hdr0 hdr1 hdr2 | payload | crc16
        hdr0 = frame TYPE (low nibble)
        hdr1 = seq (bits 7:4) | length[10:8] (bits 2:0)
        hdr2 = length[7:0]
        crc16 = CRC-16/CCITT (poly 0x1021, init 0), little-endian, over hdr0..payload
     The two framings must NOT be interleaved on the wire — mixing corrupts state.

Frame types (verified against hardware where noted):
  0 = DATA (image/response chunk, dev->host)
  1 = IDLE / ready-ack (dev->host)          [confirmed: reply to type-7]
  2 = STATUS/ERROR, payload = s16 code       [confirmed: 0xf692/0xf685/... errors]
  3 = READY / challenge (dev->host)          [confirmed: reply to type-6, pl 01000000c0]
  4 = host DATA (params/response)            [confirmed: [01][00][u32 timeout][u16 maxframe][echo]]
  5 = RESULT (dev->host, payload[0]=status)  [confirmed: pl 00 = success]
  6 = host START capture                     [confirmed]
  7 = host ABORT / RESET                     [confirmed]
  8 = BUSY / not-ready (dev->host, retry)
  9 = host keep-alive poll (no finger)
 10 = host keep-alive poll (finger present)
 0xb = EVENT / notification

Capture handshake that works (on-chip processing wrapper, FUN_1801e03c0):
  type-7 (abort)  -> type-1 (idle)
  type-6 (start)  -> type-3 (ready, payload P)
  type-4 (data = [01][00][u32 timeout][u16 maxframe][P])  -> type-5 (result, pl 00)

KNOWN LIMIT (documented, not yet solved): this on-chip exchange returns success
regardless of finger state; it does not deliver a raw image. The raw-image
streaming SM (FUN_1801e12a4/FUN_1801e07d8, type-0 DATA + type-8/9/10 poll) is
selected by higher-layer Grabber config, and the actual sensor read is performed
by a transport-object callback (vtable +0x38) whose implementation lives in the
lower USB/WinUSB function driver — NOT in the decompiled upkbu.dll/tcwbf.dll. So
the final scan trigger cannot be reconstructed from those files alone.
"""
CRC_POLY = 0x1021


def crc16(d):
    c = 0
    for b in d:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ CRC_POLY) & 0xffff if c & 0x8000 else (c << 1) & 0xffff
    return c


def frame(typ, payload=b"", seq=0):
    ln = len(payload)
    hdr = bytes([typ & 0x0f, (seq << 4) | ((ln >> 8) & 0x7), ln & 0xff])
    body = hdr + payload
    return b"Ciao" + body + crc16(body).to_bytes(2, "little")


def parse(buf):
    """Parse the first low-level frame in buf. Returns (type, seq, length, payload)."""
    j = buf.find(b"Ciao")
    if j < 0 or j + 7 > len(buf):
        return None
    h = buf[j + 4:j + 7]
    ln = ((h[1] & 0x7) << 8) | h[2]
    return (h[0] & 0x0f, h[1] >> 4, ln, buf[j + 7:j + 7 + ln])


# Ready-made host control frames (bytes verified against hardware)
ABORT = frame(7, b"\x00")   # -> device TYPE-1 idle
START = frame(6)            # -> device TYPE-3 ready
KA_NOFINGER = frame(9)
KA_FINGER = frame(10)


def type4_data(challenge, timeout_ms=5000, maxframe=2048):
    """Build the TYPE-4 host-data payload that follows a TYPE-3 ready.
    `challenge` is the TYPE-3 reply payload, echoed back."""
    return bytes([1, 0]) + timeout_ms.to_bytes(4, "little") + maxframe.to_bytes(2, "little") + challenge


if __name__ == "__main__":
    # self-check the CRCs against the known-good captured frames
    assert frame(7, b"\x00").hex() == "4369616f070001001c62", frame(7, b"\x00").hex()
    assert frame(6).hex() == "4369616f060000a0b2", frame(6).hex()
    assert frame(9).hex() == "4369616f090000919e", frame(9).hex()
    print("low-level frame CRCs OK")
