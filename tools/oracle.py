#!/usr/bin/env python3
"""
Oracle harness for cracking the UPEK 147e:2020 advanced-mode crypto handshake.

Drives the device to the live 32-byte challenge, then sends a *candidate* 96-byte
crypto response (frame 11) and reports whether the device ACCEPTED or REJECTED it.

The device is a perfect oracle:
  accept -> reply "Ciao .. 08 13 20 00 00 00 <32 bytes>"
  reject -> reply "Ciao .. 08 13 <short error>"

Plug your candidate builder into build_response(challenge, device_key) and iterate.
This is how the frame-11 blob layout + RSA/padding get pinned down against real
hardware, alongside decompilation of the vendor crypto.

Root required. See harness.py for the bring-up details.
"""
import sys, time, os, glob
import usb.core, usb.util

VID, PID = 0x147e, 0x2020

def sysfs_dev():
    for vp in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        b = os.path.dirname(vp)
        if open(vp).read().strip()=="147e" and open(b+"/idProduct").read().strip()=="2020":
            return os.path.basename(b)

def crc16(data: bytes) -> bytes:
    """Ciao frame CRC: CRC-16/CCITT (poly 0x1021, init 0x0000) over the frame
    starting after the 4-byte 'Ciao' magic, up to (not including) the 2-byte CRC.
    The 32-bit length field counts the content PLUS these 2 CRC bytes.
    Stored little-endian."""
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
    return crc.to_bytes(2, "little")

def build_frame(seq: int, sub: int, b6: int, content: bytes) -> bytes:
    """Assemble a full Ciao/0x28 frame around `content` (command bytes, no CRC)."""
    length = len(content) + 2                      # content + crc, per the len field
    head = b"Ciao" + bytes([seq, sub, b6, 0x28]) + length.to_bytes(4, "little")
    crc  = crc16(head[4:] + content)               # CRC covers everything after 'Ciao'
    return head + content + crc


def build_response(challenge: bytes, device_key: bytes) -> bytes:
    """Return the 96-byte crypto payload for `challenge`. TO BE REVERSED.

    Known: device_key is the 64-byte value the device streams in frame 6
    (candidate RSA-512 modulus / or an EC point pair -- unresolved).
    Hypotheses to test against the oracle:
      - RSA-512 PKCS1v15 encrypt of (session_key || challenge) with device_key
      - 64-byte RSA block + 32-byte MAC/echo
    """
    raise NotImplementedError("frame-11 builder not yet reversed")

STATIC = ["4369616f04000801005e01000000000d65",
          "4369616f00000728040000000604c0d6",
          "4369616f00100b280800000002040b0000006556",
          "4369616f00200b280800000051040a00000079a5",
          "4369616f00300b28080000000704200000005d11"]

def drive_to_challenge():
    d = sysfs_dev()
    open("/sys/bus/usb/drivers/usb/unbind","w").write(d); time.sleep(0.5)
    open("/sys/bus/usb/drivers/usb/bind","w").write(d);   time.sleep(1.5)
    dev = usb.core.find(idVendor=VID, idProduct=PID); usb.util.claim_interface(dev,0)
    rd = lambda t=700: (lambda r: r)(_read(dev,t))
    def _read(dev,t):
        try: return bytes(dev.read(0x81,512,t))
        except usb.core.USBError: return None
    def drain(n=8,t=600):
        o=[]
        for _ in range(n):
            r=_read(dev,t)
            if r is None: break
            o.append(r)
        return o
    dev.ctrl_transfer(0xc0,0x04,0,0,8,1000); dev.ctrl_transfer(0xc0,0x04,0,0,8,1000)
    dev.ctrl_transfer(0x40,0x0c,0x0100,0x0400,b"\x00",1000)
    drain(2,400)
    dk = b""
    for i,f in enumerate(STATIC):
        dev.write(0x02, bytes.fromhex(f), 1000); time.sleep(0.03)
        resp = b"".join(drain(6,600))
        if i==1: pass
        if i==2:
            j = resp.find(bytes.fromhex("030020002000"))
            if j>=0: dk = resp[j+6:j+6+64]
        if i==4:
            j = resp.find(bytes.fromhex("0714"))
            challenge = resp[j+2:j+2+32] if j>=0 else None
    return dev, drain, challenge, dk

def test(candidate96: bytes):
    dev, drain, challenge, device_key = drive_to_challenge()
    print("challenge :", challenge.hex())
    print("device_key:", device_key.hex())
    # frame-11 wrapper: Ciao 00 40 87 28 | len32 | 08 03 01 <fields> 60000000 <96B> | crc16
    content = bytes.fromhex("08030100000001000000310000003800000000000000030000000000000060000000") + candidate96
    frame = build_frame(0x00, 0x40, 0x87, content)
    dev.write(0x02, frame, 1000); time.sleep(0.05)
    resp = b"".join(drain(6,700))
    ok = resp[6:8]==bytes.fromhex("2b28") or (len(resp)>=16 and resp[12:14]==b"\x08\x13" and resp[14:18]==bytes.fromhex("20000000"))
    print("device says:", resp.hex())
    print("ACCEPTED" if ok else "REJECTED")
    usb.util.release_interface(dev,0)
    return ok

if __name__ == "__main__":
    # Example: read the live challenge/key without sending a response.
    dev, drain, challenge, dk = drive_to_challenge()
    print("live challenge:", challenge.hex())
    print("device key    :", dk.hex())
    usb.util.release_interface(dev,0)
