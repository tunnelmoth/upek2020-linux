#!/usr/bin/env python3
"""
Native Linux driver for the UPEK / AuthenTec TouchChip fingerprint coprocessor
USB 147e:2020 ("WBF advanced mode"), as found on ThinkPad W530 and others.

This is the device libfprint's upektc_img cannot drive and that even the vendor
libbsapi rejects with NOT_SUPPORTED. The full transport, authentication and
application-command stack was reverse-engineered from scratch (usbmon capture +
Ghidra decompilation of upkbu.dll) and is implemented here.

Layers, all verified against real hardware:

  1. Mode switch + "Ciao" transport framing (CRC-16/CCITT, poly 0x1021).
  2. Device authentication: embedded RSA-512 trust key, exponent 17.
  3. Frame-11 session auth: SHA-256(CTR4 || M || Y) proof + RSA-PKCS#1v1.5
     transport of a 48-byte session key (e=17, modulus little-endian).
  4. AES-128-CBC continuous session channel, key = SHA-256(62466e8d||Y||sk||M)[:7]+0*9,
     a single chained stream in each direction (never reset per message).
  5. Application commands: each carries an unkeyed SHA-256 integrity token.
        block = code_word(4, LE (code&0xfff)<<16)
              || body(N)
              || SHA-256(code_word || body)[:4]         <- the token
              || padding to (24+N)&~15, last pad byte = enc_len-N-9  (pad marker)
     The device recomputes the token and rejects (fixed NAK) anything else.

Root required (USB unbind/bind + raw endpoint I/O). See README / docs/CRYPTO.md.
"""
import usb.core, usb.util, time, os, glob, hashlib, secrets
try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES

# --- device-specific extracted secrets / domain-separation tags ------------------
M   = bytes.fromhex("941cf8d63afb0cff1a96531e9b28e5fe07147365e1bac869d4609cc9ad8a8804")
CTR = bytes.fromhex("e38f7cb3")

VID, PID = 0x147e, 0x2020

# --- fixed NAK the device returns for a bad integrity token / malformed command ---
NAK = bytes.fromhex("35f6f01f4ed70f4b0000000000000007")

# --- application command codes (from upkbu.dll RE) -------------------------------
CMD = {
    "get_info":   0x40c,   # body = u32 property/info-type ; reply [u32 len][data]
    "get_caps":   0x406,   # empty body ; sensor/security caps
    "get_status": 0x411,   # empty body ; unit status (contains product string)
    "get_prop32": 0x403,   # body u32 id -> u32
    "set_prop":   0x40b,   # body [u16 id][u16 len][data]
    "enum_tpl":   0x20d,   # empty ; enumerate on-chip templates
    "db_desc":    0x250,   # storage descriptor
    "get_list":   0x215,   # list/status blob
    "reset":      0x207,   # abort / reset current operation
    "capture":    0x20e,   # body mode(u32)+subop(u8)+flags(u16) ; poll for a swipe
    "capture_roi":0x20f,
    "stream_cap": 0x216,   # streaming capture (async callback transport)
    "create_obj": 0x205,   # body u16 -> u32 object id
    "consolidate":0x229,   # body u32,u32,<serialized feature set> -> [u32 result][u32 val]
    "match_tpl":  0x209,   # verify against a specific template
    "identify":   0x20a,   # identify against on-chip DB
    "del_tpl":    0x212,
}

# --- device status codes (signed 16-bit in reply word high half) -----------------
NO_FINGER   = -0x427   # 0xfbd9 : no finger present -> keep polling
NO_FINGER2  = -0x426   # 0xfbda : swipe not complete / aborted -> keep polling
MOTION      = -0x41a   # 0xfbe6 : intermediate touch/timeout -> keep polling
BADSTATE    = -0x419   # 0xfbe7 : busy / bad state
RETRY_CODES = {NO_FINGER, NO_FINGER2, MOTION, BADSTATE}


def _sysfs_path():
    for dd in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        b = os.path.dirname(dd)
        if open(dd).read().strip() == "147e" and open(b + "/idProduct").read().strip() == "2020":
            return os.path.basename(b)


def _crc16(d):
    c = 0
    for b in d:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xffff if c & 0x8000 else (c << 1) & 0xffff
    return c.to_bytes(2, "little")


def _rsa(mod64, e, msg):
    n = int.from_bytes(mod64, "little")
    ps = b""
    while len(ps) < 64 - 3 - len(msg):
        x = secrets.token_bytes(1)
        if x != b"\x00":
            ps += x
    return pow(int.from_bytes(b"\x00\x02" + ps + b"\x00" + msg, "big"), e, n).to_bytes(64, "big")


def appcmd(code, body=b""):
    """Build an application-command plaintext block (pre-AES) for `code` + `body`.

    Envelope: code_word(4) || body || SHA-256(code_word||body)[:4] || padding,
    zero-padded to enc_len = (24+len(body)) & ~15, last pad byte = enc_len-N-9.
    """
    cw  = (code << 16).to_bytes(4, "little")
    tok = hashlib.sha256(cw + body).digest()[:4]
    n   = len(body)
    enc_len = (24 + n) & ~15
    content = cw + body + tok
    pad = bytearray(enc_len - len(content))
    if pad:
        pad[-1] = len(pad) - 1
    return content + bytes(pad)


def raw_block(word, body=b""):
    """Build an app block for an arbitrary 32-bit command word (not just a code).

    Same envelope as appcmd() but the leading 4 bytes are the raw LE `word`.
    Used for async continuation frames whose word is 0x30000000 (nibble 3),
    which is not of the (code&0xfff)<<16 form.
    """
    cw = word.to_bytes(4, "little")
    tok = hashlib.sha256(cw + body).digest()[:4]
    n = len(body)
    enc_len = (24 + n) & ~15
    content = cw + body + tok
    pad = bytearray(enc_len - len(content))
    if pad:
        pad[-1] = len(pad) - 1
    return content + bytes(pad)


# async transport: command-word top nibble (bits 31..28 of the leading LE word)
NIB_DATA = 0x8   # encrypted image/data body follows
NIB_NOTIFY = 0x2  # notification — host must send a 0x30000000 continuation
CONT_WORD = 0x30000000  # host continuation word (nibble 3)


def word_nibble(dec):
    if not dec or len(dec) < 4:
        return None
    return (int.from_bytes(dec[0:4], "little") >> 28) & 0xf


def is_nak(dec):
    return dec is not None and dec[:8] == NAK[:8]


def status16(dec):
    """Signed 16-bit device status from a reply block (high half of the reply word)."""
    if not dec or len(dec) < 2:
        return None
    s = int.from_bytes(dec[0:2], "little")
    return s if s < 0x8000 else s - 0x10000


def reply_len(dec):
    return int.from_bytes(dec[4:8], "little") if dec and len(dec) >= 8 else 0


def reply_body(dec):
    """Payload following the [word:4][u32 len:4] reply header, clamped to len."""
    if not dec or len(dec) < 8:
        return b""
    n = reply_len(dec)
    return dec[8:8 + n] if 8 + n <= len(dec) else dec[8:]


class Upek:
    def __init__(self):
        p = _sysfs_path()
        if not p:
            raise RuntimeError("147e:2020 not found on USB")
        open("/sys/bus/usb/drivers/usb/unbind", "w").write(p); time.sleep(0.5)
        open("/sys/bus/usb/drivers/usb/bind", "w").write(p);   time.sleep(1.8)
        d = None
        for _ in range(25):
            d = usb.core.find(idVendor=VID, idProduct=PID)
            if d:
                break
            time.sleep(0.4)
        if not d:
            raise RuntimeError("device did not re-enumerate after bind")
        usb.util.claim_interface(d, 0)
        self.d = d
        self.sub = 0x50
        self.txc = self.rxc = None

    # --- raw transport ----------------------------------------------------------
    def _rd(self, t=800):
        try:
            return bytes(self.d.read(0x81, 512, t))
        except usb.core.USBError:
            return None

    def _drain(self, n=14, t=500):
        o = []
        for _ in range(n):
            r = self._rd(t)
            if r is None:
                break
            o.append(r)
        return o

    def _wr(self, h):
        self.d.write(0x02, bytes.fromhex(h) if isinstance(h, str) else h, 1000)

    def _bf(self, seq, sub, b6, content):
        head = b"Ciao" + bytes([seq, sub, b6, 0x28]) + (len(content) + 2).to_bytes(4, "little")
        return head + content + _crc16(head[4:] + content)

    def _frames(self, r):
        out, i = [], 0
        while True:
            j = r.find(b"Ciao", i)
            if j < 0 or j + 12 > len(r):
                break
            lenf = int.from_bytes(r[j + 8:j + 12], "little")
            out.append((r[j + 5], r[j + 12:j + 12 + lenf - 2]))
            i = j + 12 + lenf
        return out

    # --- session bring-up -------------------------------------------------------
    def handshake(self, fmt=0x31):
        # fmt is the session image-format field in the 0x308 open. 0x31 opens a
        # raw-image-grab session (capture over the low-level frame channel);
        # fmt=0 opens a managed session where the on-chip template/object
        # subsystem (create_obj/db_desc/begin-op/consolidate) is live.
        d = self.d
        d.ctrl_transfer(0xc0, 0x04, 0, 0, 8, 1000); d.ctrl_transfer(0xc0, 0x04, 0, 0, 8, 1000)
        d.ctrl_transfer(0x40, 0x0c, 0x0100, 0x0400, b"\x00", 1000); self._drain(2, 400)
        devkey = Y = None
        for i, f in enumerate([
                "4369616f04000801005e01000000000d65",
                "4369616f00000728040000000604c0d6",
                "4369616f00100b280800000002040b0000006556",
                "4369616f00200b280800000051040a00000079a5",
                "4369616f00300b28080000000704200000005d11"]):
            self._wr(f); time.sleep(0.03); r = b"".join(self._drain(6, 600))
            if i == 2:
                j = r.find(bytes.fromhex("030020002000")); devkey = r[j + 6:j + 6 + 64]
            if i == 4:
                j = r.find(b'\x07\x14'); Y = r[j + 2:j + 2 + 32]
        sk = secrets.token_bytes(48)
        # 0x308 body: code(2) | u32[0]=1 | u32[1]=1 | u32[2]=fmt | u32[3]=bpp 0x38 |
        # u32[4]=0 | u32[5]=3 | u32[6]=0 | u32[7]=0x60. fmt selects raw vs managed.
        body308 = (b"\x08\x03"
                   + (1).to_bytes(4, "little") + (1).to_bytes(4, "little")
                   + fmt.to_bytes(4, "little") + (0x38).to_bytes(4, "little")
                   + (0).to_bytes(4, "little") + (3).to_bytes(4, "little")
                   + (0).to_bytes(4, "little") + (0x60).to_bytes(4, "little"))
        content = (body308 + hashlib.sha256(CTR + M + Y).digest() + _rsa(devkey, 17, sk))
        self._wr(self._bf(0, 0x40, 0x87, content)); time.sleep(0.05)
        resp = b"".join(self._drain(8, 800))
        assert resp[12:14] == b'\x08\x13', "frame-11 rejected: " + resp[12:20].hex()
        aeskey = hashlib.sha256(bytes.fromhex("62466e8d") + Y + sk + M).digest()[:7] + b"\x00" * 9
        self.txc = AES.new(aeskey, AES.MODE_CBC, b"\x00" * 16)
        self.rxc = AES.new(aeskey, AES.MODE_CBC, b"\x00" * 16)
        return self

    # --- application command transceive ----------------------------------------
    def cmd(self, block, tmo=800):
        """Encrypt+send an application block, return (decrypted_reply, raw)."""
        pl = block + b"\x00" * ((16 - len(block) % 16) % 16)
        ct = self.txc.encrypt(pl)
        self._wr(self._bf(0, self.sub, 0x17, bytes.fromhex("0080") + ct)); time.sleep(0.05)
        self.sub = (self.sub + 0x10) & 0xff
        r = b"".join(self._drain(14, tmo))
        dec = b""
        for _sub, content in self._frames(r):
            if content[:2] == b"\x00\x80":
                cip = content[2:]; nn = (len(cip) // 16) * 16
                if nn >= 16:
                    dec += self.rxc.decrypt(cip[:nn])
        return (dec if dec else None), r

    def call(self, name_or_code, body=b"", tmo=800):
        code = CMD[name_or_code] if isinstance(name_or_code, str) else name_or_code
        return self.cmd(appcmd(code, body), tmo=tmo)

    # --- high-level operations (verified: info/caps/status/enumerate/capture) ----
    def get_info(self, info_type=5):
        dec, _ = self.call("get_info", info_type.to_bytes(4, "little"))
        return None if is_nak(dec) else reply_body(dec)

    def get_status(self):
        dec, _ = self.call("get_status")
        return None if is_nak(dec) else dec

    def get_caps(self):
        dec, _ = self.call("get_caps")
        return None if is_nak(dec) else dec

    def enum_templates(self):
        dec, _ = self.call("enum_tpl")
        if is_nak(dec):
            return None
        return reply_len(dec), reply_body(dec)

    def reset(self):
        return self.call("reset")

    def capture_once(self, mode=0x00040000, subop=0, flags=1, tmo=1200):
        """One capture poll. Returns (status, reply_block). status==0 => template
        blob in reply_body(); status in RETRY_CODES => no finger yet."""
        body = mode.to_bytes(4, "little") + bytes([subop]) + flags.to_bytes(2, "little")
        dec, raw = self.call("capture", body, tmo=tmo)
        if is_nak(dec) or dec is None:
            return None, dec
        return status16(dec), dec

    def capture(self, timeout_s=30.0, mode=0x00040000, on_poll=None):
        """Poll capture until a finger is read or timeout. Returns the template/
        feature blob (bytes) on success, or None on timeout."""
        deadline = time.time() + timeout_s
        polls = 0
        while time.time() < deadline:
            st, dec = self.capture_once(mode=mode)
            polls += 1
            if st is None:
                time.sleep(0.15); continue
            if st in RETRY_CODES:
                if on_poll:
                    on_poll(polls, st)
                time.sleep(0.12); continue
            if st == 0:
                return reply_body(dec)
            # any other status: hard error, stop
            return None
        return None

    def async_stream(self, code, body, ack_fn=None, timeout_s=30.0, tmo=400):
        """Drive an asynchronous operation (0x216 stream / 0x212 begin-op) through
        the continuation loop.

        The device replies with notification frames (word nibble 0x2); for each,
        the host sends a 0x30000000 continuation carrying a 1-byte ack, until a
        terminal frame (nibble != 0x2) arrives. Image/feature data rides in
        nibble-0x8 frames in between. `ack_fn(dec)->int` decides the ack byte
        (default 1 = keep going).

        NOTE: this requires the sensor to be armed first via the operation-open
        prologue; issued cold, the op command terminates immediately with an error.
        """
        dec, raw = self.cmd(appcmd(code, body), tmo=tmo)
        deadline = time.time() + timeout_s
        blobs = []
        while time.time() < deadline:
            if dec is None or is_nak(dec):
                return None, blobs
            nib = word_nibble(dec)
            if nib == NIB_DATA:
                blobs.append(dec[4:])
            elif nib != NIB_NOTIFY:
                return status16(dec), blobs   # terminal
            ack = 1 if ack_fn is None else ack_fn(dec)
            dec, raw = self.cmd(raw_block(CONT_WORD, bytes([ack])), tmo=tmo)
        return None, blobs

    # --- raw-image scan (vendor control 0x0c, verified scan-trigger opcode) ---
    def scan_start(self):
        """Arm the sensor front-end and begin raw-image streaming.
        Vendor control OUT: bRequest 0x0c, wValue 0x0100, wIndex 0x0601.
        (wIndex 0x0400 = command-mode kick, done in handshake; 0x0601 = START,
        0x0602 = STOP.) After this, image lines arrive as "Ciao" type-0 frames on
        EP 0x81 while a finger is on the sensor."""
        self.d.ctrl_transfer(0x40, 0x0c, 0x0100, 0x0601, b"\x00", 1000)

    def scan_stop(self):
        self.d.ctrl_transfer(0x40, 0x0c, 0x0100, 0x0602, b"\x00", 1000)

    def capture_image(self, timeout_s=20.0):
        """Start a scan and collect raw-image bytes from EP 0x81 until timeout.
        Returns the concatenated bulk payload (strip "Ciao" type-0 headers to get
        pixels; sensor is 8-bit grayscale up to 508x508). A swipe must occur within
        the window. NOTE: verified that 0x0601 is accepted; live pixel capture is
        pending a physical swipe on hardware."""
        self.scan_start()
        buf = bytearray()
        deadline = time.time() + timeout_s
        try:
            while time.time() < deadline:
                try:
                    r = bytes(self.d.read(0x81, 4096, 200))
                    if r and len(r) != 2:
                        buf += r
                except usb.core.USBError:
                    pass
        finally:
            try:
                self.scan_stop()
            except Exception:
                pass
        return bytes(buf)

    def close(self):
        try:
            usb.util.release_interface(self.d, 0)
        except Exception:
            pass


if __name__ == "__main__":
    # Smoke test: bring up the channel and read device identity (no finger needed).
    u = Upek(); u.handshake()
    print("channel up")
    st = u.get_status()
    if st:
        # product string is ASCII inside the status blob
        printable = bytes(c if 32 <= c < 127 else 0x2e for c in st)
        print("status:", st.hex())
        print("ascii :", printable.decode("latin1"))
    info = u.get_info(5)
    print("info(5):", info.hex() if info else None)
    n, _ = u.enum_templates()
    print("enrolled templates on chip:", n)
    u.close()
