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
| Drive the device from Linux (mode switch + transport) | **done** — see `tools/harness.py` |
| Reach the per-session crypto challenge | **done** |
| Prove no host secret is required (no "wall") | **done** — see `docs/CRYPTO.md` |
| Extract the embedded trust-anchor public key | **done** — `data/trust_key.pem` |
| frame-12 blob layout + AES channel derivation | in progress |
| on-chip enroll / verify command set | todo |
| `libfprint` match-on-chip driver | todo |

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
docs/PROTOCOL.md     the "Ciao" transport framing and the full handshake sequence
docs/CRYPTO.md       the crypto model, the feasibility proof, the extracted trust key
docs/METHODOLOGY.md  how it was captured and reversed (VM + usbmon + Ghidra)
tools/harness.py     user-space libusb harness: init -> live challenge
tools/usbpcap.py     minimal usbmon pcap decoder (linktype 220)
data/handshake.txt   one fully-decoded handshake, annotated
data/trust_key.pem   the RSA-512 trust anchor extracted from the driver
```

## Quickstart

```
sudo apt install python3-usb libusb-1.0-0      # or your distro's equivalent
sudo python3 tools/harness.py
```

Expected: the device replies to `get_info`, streams its static public key, and
finally emits a fresh 32-byte challenge — the point where the cryptographic
session begins.

## Scope and ethics

Interoperability reverse engineering of a device the owner physically possesses,
to run it on a free operating system. No proprietary binaries, no decompiled
vendor code, and no fingerprint data are included in this repository — only
independently-authored code and protocol documentation. The one embedded public
key is reproduced because it is, by definition, public and is required for interop.

## License

GPL-3.0-or-later. See `LICENSE`.
