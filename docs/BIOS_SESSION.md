# The BIOS (keytype-0x21) POST session

The stock Lenovo BIOS talks to this reader at **every POST** through an EFI
module — *TCBiolib 4.6.2 / "TouchChip BIOS Extension"* ("Upek Fingerprint Reader
Driver for Lenovo"). Under **coreboot/libreboot that module never runs**, so the
reader comes up cold and the only thing that ever opens a session with it is the
OS driver. This document reconstructs the exact POST session, reversed from the
BIOS module, so it can be replayed from Linux (`tools/bios_session.py`).

## Two session variants

The reader implements two authenticated session "keytypes", both keyed off the
same 32-byte pre-shared trust anchor `M` (public, baked into the firmware — see
`docs/CRYPTO.md`), so **neither needs a per-machine secret**:

| | keytype **1** (OS driver) | keytype **0x21** (BIOS/POST) |
|---|---|---|
| entry | `tools/upek2020.py` / `upeklib.py` | `tools/bios_session.py` |
| MAC | `SHA256(0xe38f7cb3 ‖ M ‖ Y)` | `SHA256(0x4652a3d1 ‖ M ‖ device_nonce)` |
| key exchange | RSA-512 encrypted 48-byte session key | 32-byte host nonce (no RSA) |
| app cipher | AES-128-CBC | **single DES-CBC** (56-bit) |
| session key | `SHA256(0x8d6e4662 ‖ Y ‖ sk ‖ M)[:7]` | `SHA256(0x8d6e4662 ‖ device_nonce ‖ host_nonce ‖ M)[:8]` |

## Transport: the reliable-link app-header

Every command rides a Ciao type-0 frame whose payload is prefixed with a 3-byte
reliable-link header `0x28 | len16(content)`; the command word follows that:

```
"Ciao" | 00 | (seq<<4)|lenHi | lenLo | 28 aplen_lo aplen_hi | <content> | crc16
```

`seq` is a 4-bit counter incremented on every successful command/reply round
(reset to 0 at connect). CRC-16/CCITT (poly 0x1021, init 0) is computed over the
three Ciao header bytes + payload; the `"Ciao"` magic itself is not covered.
Omitting the `0x28` app-header makes the device answer with a malformed-frame
error (`38 45 f4`, a valid Ciao frame carrying error -0xbbb).

## Handshake sequence (byte-exact)

`bios_session.py::handshake()` sends, on a **freshly bound** device and as the
**first** crypto exchange (doing the keytype-1/RSA handshake first locks the
cipher mode and this open then returns `-0x8ac` "unsupported in this mode"):

```
connect:  CTRL-OUT 40 0c 0100 0400 len1 data=00      ; then read the type-3 hello
0x406 s0: 43 69 61 6f 00 00 07 28 04 00 00 00 06 04 c0 d6            GetDeviceInfo
0x411 s1: 43 69 61 6f 00 10 07 28 04 00 00 00 11 04 da 1f            GetExtInfo
0x407 s2: 43 69 61 6f 00 20 0b 28 08 00 00 00 07 04 20 00 00 00 e9 07  GetRandom(0x20)
0x308 s3: 43 69 61 6f 00 30 67 28 64 00 | 00 00 08 03 00 00 00 00 01 00 00 00
          21 00 00 00 38 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 40 00 00 00
          <32B host-MAC> <32B host-nonce> <crc16>
```

- host-MAC = `SHA256(LE32(0x4652a3d1) ‖ M ‖ device_nonce)` (device_nonce is the
  32 bytes returned by 0x407).
- The device accepts with reply word `0000 0813` (status 0) and returns its own
  32-byte confirmation.
- **DES key** = `SHA256(LE32(0x8d6e4662) ‖ device_nonce ‖ host_nonce ‖ M)[:8]`.

## Application channel: single DES-CBC

After the handshake, every command is DES-CBC encrypted (`bios_session.py::cmd`):

```
plaintext = cmd_word(4) ‖ body
mac4      = SHA256(plaintext)[:4]
region    = plaintext ‖ mac4 ‖ zero_pad ‖ padlen_byte     ; padded to a multiple of 8
ciphertext= DES-CBC(region)                               ; key above, IV chained
wire      = 00 00 00 80 ‖ ciphertext                      ; marker 0x80000000 (plaintext)
```

The IV is 0 at session start and **chained** across commands (the mode field
= 3 in the 0x308 body suppresses the per-command IV reset). Two independent
DES-CBC contexts run — one outbound, one inbound — each IV-chained. Replies whose
first dword has top nibble 8 (`0x8xxxxxxx`) are encrypted; strip the 4-byte
marker and DES-CBC-decrypt to `response ‖ mac4 ‖ pad`.

**Verified end to end:** over this channel `GetProperty(0x63C458FB)` decrypts to
the reader's 177-byte sensor-config blob, which begins with the ASCII signature
`TBXLITE` and whose analog scan-mode bits are already set (persisted in the
reader's NVRAM). `bios_session.py`'s smoke test reads it.

## What this does and does not unlock

The keytype-0x21 session is exactly what the stock BIOS establishes at POST — the
one thing coreboot skips. It comes up cleanly and the encrypted channel works
(config read, high-security pairing query `0x424` accepted). **But on the unit
tested it does not make the analog sensor scan:** in this session `0x20e` capture
still polls `NO_FINGER` unchanged by a finger, exactly as in the keytype-1
session, and every finger-status channel (interrupt EP 0x83, the C0/04 status
register, the frame channel) stays silent. See the repository README for the
overall status and the hardware conclusion.
