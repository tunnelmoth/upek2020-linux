#!/usr/bin/env python3
"""bios_session.py - the BIOS-side (keytype 0x21) secure session for the
UPEK/AuthenTec TouchChip (USB 147e:2020).

The stock Lenovo BIOS talks to this reader at every POST via the TCBiolib EFI
module ("TouchChip BIOS Extension", TCBiolib 4.6.2). Under coreboot/libreboot
that module never runs, so the reader comes up cold and only ever sees the OS
driver. This file is an independent, from-scratch reimplementation of the exact
POST session TCBiolib establishes, so it can be replayed from Linux.

Two distinct session ("keytype") variants exist and were both reversed:

  * keytype 1  (upek2020.py / upeklib.py) - the OS-driver session:
    SHA-256(0xe38f7cb3 || M || Y) MAC + RSA-512-encrypted 48-byte session key,
    AES-128-CBC application channel. This is what libfprint-class drivers use.

  * keytype 0x21 (this file) - the BIOS/POST session:
    SHA-256(0x4652a3d1 || M || device_nonce) MAC, a 32-byte host nonce (no RSA),
    and a **single DES-CBC** application channel keyed from the handshake. This
    is the session the stock BIOS opens at power-on.

Both authenticate with the same 32-byte pre-shared value M (the "trust anchor"
baked into every copy of the firmware, extracted independently), so no
per-machine secret is required for either.

Transport: the low-level "Ciao" frame carries a reliable-link app-header
`0x28 | len16` before the command word; see relframe(). Commands after the
handshake are wrapped in the keytype-0x21 write envelope (marker 0x80000000 +
DES-CBC(cmd||body||SHA256(msg)[:4]||pad)).

Requires: pyusb, pycryptodome (Crypto.Cipher.DES), and the shared M/CTR
constants. Run as root (claims the interface).
"""
import time
import hashlib
import secrets
import glob
import os
import usb.core
import usb.util
try:
    from Crypto.Cipher import DES
except ImportError:
    from Cryptodome.Cipher import DES

VID, PID = 0x147e, 0x2020
# 32-byte pre-shared trust anchor (public; baked into the firmware, extracted).
M = bytes.fromhex("941cf8d63afb0cff1a96531e9b28e5fe07147365e1bac869d4609cc9ad8a8804")
# keytype-0x21 KDF/MAC prefixes (little-endian 32-bit tags, from TCBiolib).
MAC_HOST = 0x4652a3d1      # host->device MAC:  SHA256(tag || M || device_nonce)
MAC_DEV  = 0xfb427472      # device->host MAC:  SHA256(tag || M || host_nonce)
KDF_SESS = 0x8d6e4662      # session key: SHA256(tag || device_nonce || host_nonce || M)


def _crc16(d):
    c = 0
    for b in d:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xffff if c & 0x8000 else (c << 1) & 0xffff
    return c.to_bytes(2, "little")


def _le32(x):
    return x.to_bytes(4, "little")


def relframe(seq, content):
    """Build a Ciao type-0 frame with the reliable-link app-header.

    Wire: "Ciao" | 0x00 | (seq<<4)|lenHi | lenLo | 0x28 aplen16 | content | crc16
    where the payload = [0x28][len(content) LE16] + content, and the 11-bit
    Ciao length covers that whole payload. CRC-16/CCITT over the 3 Ciao header
    bytes + payload (the "Ciao" magic itself is not covered).
    """
    ah = bytes([0x28, len(content) & 0xff, (len(content) >> 8) & 0xff])
    payload = ah + content
    ch = bytes([0x00, ((seq & 0xf) << 4) | ((len(payload) >> 8) & 0x7), len(payload) & 0xff])
    return b"Ciao" + ch + payload + _crc16(ch + payload)


def _sysfs_port():
    for dd in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        if open(dd).read().strip() == "147e" and \
           open(os.path.dirname(dd) + "/idProduct").read().strip() == "2020":
            return os.path.basename(os.path.dirname(dd))


class BiosSession:
    """The keytype-0x21 (BIOS/POST) session with a single-DES-CBC channel."""

    def __init__(self):
        p = _sysfs_port()
        open("/sys/bus/usb/drivers/usb/unbind", "w").write(p); time.sleep(0.5)
        open("/sys/bus/usb/drivers/usb/bind", "w").write(p); time.sleep(1.8)
        d = None
        for _ in range(25):
            d = usb.core.find(idVendor=VID, idProduct=PID)
            if d:
                break
            time.sleep(0.4)
        usb.util.claim_interface(d, 0)
        self.d = d
        self.seq = 0
        self.eiv = b"\x00" * 8   # outbound DES-CBC IV (chained across commands)
        self.div = b"\x00" * 8   # inbound  DES-CBC IV (chained across replies)
        self.key = None

    # -- low-level frame I/O -----------------------------------------------------
    def _drain(self, n=8, t=700):
        out = []
        for _ in range(n):
            try:
                out.append(bytes(self.d.read(0x81, 512, t)))
            except usb.core.USBError:
                break
        return b"".join(out)

    def _raw(self, content, dn=8, t=700):
        """Send one reliable-link frame at the current seq, return the reply bytes."""
        self.d.write(0x02, relframe(self.seq, content), 800)
        self.seq = (self.seq + 1) & 0xf
        time.sleep(0.04)
        return self._drain(dn, t)

    # -- handshake ---------------------------------------------------------------
    def handshake(self):
        """Run the exact BIOS POST sequence: connect, 0x406, 0x411, 0x407 (get
        device nonce), then 0x308 keytype-0x21. Derives the DES session key.

        Must be the FIRST crypto command to the device: doing the OS-driver
        keytype-1 handshake first locks the reader into that cipher mode and the
        keytype-0x21 open then returns -0x8ac ("unsupported in this mode").
        """
        d = self.d
        d.ctrl_transfer(0xc0, 0x04, 0, 0, 8, 1000); d.ctrl_transfer(0xc0, 0x04, 0, 0, 8, 1000)
        d.ctrl_transfer(0x40, 0x0c, 0x0100, 0x0400, b"\x00", 1000)
        time.sleep(0.05); self._drain(3, 400)                          # type-3 hello
        self._raw(bytes.fromhex("00000604"))                           # 0x406 GetDeviceInfo
        self._raw(bytes.fromhex("00001104"))                           # 0x411 GetExtInfo
        r407 = self._raw(bytes.fromhex("0000070420000000"))            # 0x407 GetRandom(0x20)
        j = r407.find(bytes.fromhex("0714"))
        device_nonce = r407[j + 2:j + 2 + 32]
        host_nonce = secrets.token_bytes(32)
        host_mac = hashlib.sha256(_le32(MAC_HOST) + M + device_nonce).digest()
        inner = (bytes.fromhex("00000803")          # cmd word 0x03080000
                 + _le32(0) + _le32(1)               # result, sub-command=1
                 + _le32(0x21) + _le32(0x38)         # keytype=0x21, keybits=0x38 (DES-56)
                 + _le32(0) + _le32(3) + _le32(0)    # flags, mode=3, ...
                 + _le32(0x40)                       # marker
                 + host_mac + host_nonce)
        r308 = self._raw(inner, 10, 900)
        if b"\x08\x13" not in r308:
            raise RuntimeError("0x308 keytype-0x21 rejected: " + r308.hex()[:32])
        # single DES key = first 8 bytes of the session KDF output.
        self.key = hashlib.sha256(_le32(KDF_SESS) + device_nonce + host_nonce + M).digest()[:8]
        return self

    # -- encrypted application channel ------------------------------------------
    def cmd(self, code, body=b"", dn=10, t=1000):
        """Send an application command over the keytype-0x21 DES-CBC channel and
        return the decrypted reply block (word || u32 len || data ...)."""
        pt = _le32(code << 16) + body
        mac4 = hashlib.sha256(pt).digest()[:4]
        base = pt + mac4
        total = ((len(base) + 1 + 7) // 8) * 8
        padlen = total - len(base) - 1
        region = base + b"\x00" * padlen + bytes([padlen])
        ci = DES.new(self.key, DES.MODE_CBC, self.eiv)
        ct = ci.encrypt(region)
        self.eiv = ct[-8:]                                   # chain outbound IV
        wire = bytes.fromhex("00000080") + ct                # 0x80000000 marker + ciphertext
        r = self._raw(wire, dn, t)
        j = r.find(b"Ciao")
        if j < 0:
            return None
        ln = ((r[j + 5] & 0x7) << 8) | r[j + 6]
        pay = r[j + 7:j + 7 + ln]
        wl = pay[1] | (pay[2] << 8)
        wr = pay[3:3 + wl]
        if (int.from_bytes(wr[:4], "little") >> 28) != 8:    # plaintext reply
            return wr
        rct = wr[4:]
        rct = rct[:(len(rct) // 8) * 8]
        ci = DES.new(self.key, DES.MODE_CBC, self.div)
        dec = ci.decrypt(rct)
        self.div = rct[-8:] if rct else self.div             # chain inbound IV
        return dec

    def status16(self, dec):
        if not dec or len(dec) < 2:
            return None
        x = int.from_bytes(dec[0:2], "little")
        return x if x < 0x8000 else x - 0x10000

    def close(self):
        try:
            usb.util.release_interface(self.d, 0)
        except Exception:
            pass


if __name__ == "__main__":
    # Smoke test: open the BIOS keytype-0x21 session and read a device property
    # over the DES channel. Proves the whole crypto/transport stack end to end.
    s = BiosSession().handshake()
    print("keytype-0x21 session up, DES key:", s.key.hex())
    dec = s.cmd(0x402, (0x63C458FB).to_bytes(4, "little"))   # GetProperty(sensor config)
    print("0x402 status:", s.status16(dec))
    print("0x402 reply :", dec.hex() if dec else None)
    print("TBXLITE sig :", bool(dec and b"TBXLITE" in dec))  # sensor config blob signature
    s.close()
