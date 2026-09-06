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


import hashlib, secrets

# Domain-separation tag and the device's long-term secret (device-specific, extracted).
CTR4 = bytes.fromhex("e38f7cb3")
M    = bytes.fromhex("941cf8d63afb0cff1a96531e9b28e5fe07147365e1bac869d4609cc9ad8a8804")

def build_response(Y: bytes, device_key: bytes) -> bytes:
    """Return the 96-byte frame-11 crypto payload. SOLVED and verified against
    real hardware (device replies 08 13 20 = accept).

    payload = SHA-256(CTR4 || M || Y)                          # 32 bytes
           || RSA-encrypt(session_key)                          # 64 bytes
    RSA: n = int(device_key, 'little'), e = 17, PKCS#1 v1.5 type 2,
         session_key = 48 random bytes, ciphertext big-endian.
    `Y` is the 32-byte reply to the 07-04 command; `device_key` is the 64-byte
    value from frame 6.
    """
    h = hashlib.sha256(CTR4 + M + Y).digest()
    n = int.from_bytes(device_key, "little")
    sk = secrets.token_bytes(48)
    ps = b""
    while len(ps) < 64 - 3 - len(sk):
        x = secrets.token_bytes(1)
        if x != b"\x00": ps += x
    block = b"\x00\x02" + ps + b"\x00" + sk
    ct = pow(int.from_bytes(block, "big"), 17, n).to_bytes(64, "big")
    return h + ct

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


def channel_key(Y: bytes, session_key: bytes) -> bytes:
    """Derive the AES-128-ECB channel key for the post-handshake session.

    aes_key = SHA-256(62466e8d || Y || session_key || M)[:7] + b"\x00"*9
    Verified against hardware. Channel is AES-128-ECB.
    """
    kdf = hashlib.sha256(bytes.fromhex("62466e8d") + Y + session_key + M).digest()
    return kdf[:7] + b"\x00" * 9
