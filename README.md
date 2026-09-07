# upek2020-linux

Reverse-engineering the **UPEK / AuthenTec TouchChip Fingerprint Coprocessor
("WBF advanced mode", USB `147e:2020`)** with the goal of a working Linux driver.

This coprocessor ships in many 2011-2013 ThinkPads (X230, T430/T530, W530, …).
Under Linux it is effectively dead: `libfprint`'s `upektc_img` driver targets the
*image* sensors and cannot talk to the encrypted, match-on-chip "advanced mode"
of this part. This repo documents the protocol and the crypto, and provides a
user-space harness that drives the device far enough to prove a native driver is
feasible.

## Status

| Milestone | State |
|---|---|
| Drive the device from Linux (mode switch + transport) | **done** — `tools/harness.py` |
| Reach the per-session crypto challenge | **done** |
| Prove no host secret is required (no "wall") | **done** — `docs/CRYPTO.md` |
| Extract the embedded trust-anchor public key | **done** — `data/trust_key.pem` |
| frame-11 auth + AES-128-CBC session channel | **done** — `docs/CRYPTO.md` |
| Application-command envelope (SHA-256 token) | **done** — `docs/APP_PROTOCOL.md` |
| Full command set unlocked (info/caps/status/enum/capture/...) | **done** — `tools/upek2020.py` |
| Capture command (0x20e) drives the sensor to poll for a swipe | **done** — returns no-finger status; live template read pending a physical swipe |
| BIOS (keytype-0x21) POST session + single-DES-CBC channel | **done** — `tools/bios_session.py`, `docs/BIOS_SESSION.md` |
| on-chip enroll / verify state machine | commands mapped; live capture blocked (see note) |
| `libfprint` match-on-chip driver | scaffolded — `tools/upekdrv.py` |

### Note: the analog wall (unit-specific)

Both authenticated sessions come up and the full command set works, but on the
unit tested **the analog sensor produces no signal on a finger** — the capture
command polls `NO_FINGER` unchanged, and every finger-status channel (interrupt
EP 0x83, the C0/04 status register, the frame channel) stays silent. The stock
BIOS's exact POST session (keytype-0x21 handshake + DES channel + config +
capture) was reimplemented from the BIOS module and replayed faithfully from
Linux (`tools/bios_session.py`), and it does **not** change this. With the
digital coprocessor fully functional, the physical sensor surface intact, and a
byte-faithful BIOS-session replay not waking the analog front end, the evidence
points to an **internal analog-path hardware fault** on this specific reader
(dead front end, or a broken sensing-strip↔coprocessor connection). The protocol
work stands and drives any working `147e:2020`; the missing piece here is
hardware, not software.

## The headline result

The Windows driver's host side uses **only** `CryptImportKey`, `CryptVerifySignature`,
`CryptGenRandom` and hashing. It **never** signs, decrypts, or exports a key, and
the binaries embed **exactly one** RSA key — a *public* one. In other words the host
holds **no secret**: it authenticates the device with a baked-in public key, generates
a random session key, and RSA-encrypts it to the device's own public key.

That means the encrypted, challenge-bound handshake **can be reimplemented on Linux
without any vendor private key**. There is no cryptographic wall. See `docs/CRYPTO.md`.

## Layout

```
docs/PROTOCOL.md      the "Ciao" transport framing and the full handshake sequence
docs/CRYPTO.md        the crypto model, the feasibility proof, the extracted trust key
docs/APP_PROTOCOL.md  application-command envelope (SHA-256 token), command map, capture
docs/METHODOLOGY.md   how it was captured and reversed (VM + usbmon + Ghidra)
tools/upek2020.py     the driver: handshake + AES channel + app commands + capture poll
tools/harness.py      user-space libusb harness: init -> live challenge
tools/usbpcap.py      minimal usbmon pcap decoder (linktype 220)
data/handshake.txt    one fully-decoded handshake, annotated
data/trust_key.pem    the RSA-512 trust anchor extracted from the driver
```

## Quickstart

```
sudo apt install python3-usb python3-pycryptodome libusb-1.0-0   # or distro equivalent
sudo python3 tools/upek2020.py
```

Expected output — the full encrypted session comes up and the device identifies
itself and reports its on-chip template store:

```
channel up
status: ...4c656e6f766f2054434435312d5443533544...
ascii : ...Lenovo TCD51-TCS5D POA...
info(5): 0301030001010103...
enrolled templates on chip: 0
```

`tools/harness.py` remains as the minimal transport-only bring-up (init -> live
32-byte challenge) if you want to inspect the handshake in isolation.

## Scope and ethics

Interoperability reverse engineering of a device the owner physically possesses,
to run it on a free operating system. No proprietary binaries, no decompiled
vendor code, and no fingerprint data are included in this repository — only
independently-authored code and protocol documentation. The one embedded public
key is reproduced because it is, by definition, public and is required for interop.

## License

GPL-3.0-or-later. See `LICENSE`.
