# Crypto model and feasibility proof

## Question

The advanced-mode session is encrypted and the host's 96-byte handshake response
is bound to a fresh per-session challenge (verified: replaying it with the wrong
challenge is rejected). So the handshake cannot be replayed. The decisive question
for a Linux port is: **does the host need a secret we do not have** (e.g. a vendor
private key), or can any client complete the handshake?

## Evidence

### 1. The host performs no private-key operation

The complete Windows CryptoAPI import set of both driver modules (the WBF driver
and the BSAPI layer) is:

```
CryptImportKey            CryptCreateHash      CryptGenRandom
CryptVerifySignature      CryptHashData        CryptAcquireContext
CryptMsgClose/GetParam    CryptQueryObject     Cert{Find,Get,Close,Free}
```

Absent: `CryptEncrypt`, `CryptDecrypt`, `CryptSignHash`, `CryptExportKey`,
and any `BCrypt*` private-key call.

So through the OS crypto stack the host only ever **verifies** signatures,
**hashes**, and **generates randomness** — it never signs and never decrypts.

### 2. Only a public key is embedded

Scanning both binaries for key material:

```
RSA1 (CryptoAPI PUBLICKEYBLOB)  : 1 per module
RSA2 (CryptoAPI PRIVATEKEYBLOB) : 0
PKCS#1 / PKCS#8 private keys     : 0
```

There is exactly one embedded RSA key and it is **public**. No private key,
in any format, anywhere in the driver.

### 3. The extracted trust anchor

The single embedded key (identical in both modules):

- RSA-512, `e = 65537`, `aiKeyAlg = CALG_RSA_SIGN` (a signature-verification key).
- Provided as `data/trust_key.pem`.

Its role is to **verify the device's identity**: the device presents a
certificate/signature that chains to this key, and the host checks it. Weak by
modern standards (512-bit), but we use it as-is for interop, not to attack it.

## Model

1. The device sends its per-device RSA-512 public key in the clear (handshake
   frame 6, static) together with a signature.
2. The host verifies that signature against the embedded RSA-512 trust key
   (`CryptVerifySignature` + certificate parsing) — **authenticating the device**.
3. The device sends a 32-byte challenge (frame 10).
4. The host generates a random session key (`CryptGenRandom`), forms a blob that
   includes the challenge, and RSA-**encrypts** it with the *device's* public key
   (a public-key operation, done via the statically-linked crypto library). This
   is the 96-byte frame 11.
5. The device decrypts on-chip with its private key, checks the challenge, and
   derives the shared session key.
6. An AES channel carries on-chip enrollment and matching.

## Conclusion

Every key the host touches is either **public** (the trust anchor, and the device's
own key) or **freshly generated random** (the session key). The host needs **no
vendor secret**. Therefore the handshake is reimplementable on Linux, and a native
match-on-chip driver is feasible. The remaining work is engineering, not secrets:
recover the exact frame-11 blob layout and the AES key-derivation, then the on-chip
enroll/verify command set, and expose it through `libfprint`'s device-storage
(match-on-chip) API.

## Deeper reversing status

Static analysis of the BSAPI layer refines the picture without changing the verdict:

- Crypto-API profile (BSAPI module): `CryptGenRandom` x3, `CryptImportKey` x1,
  `CryptVerifySignature` x1; `CryptEncrypt` / `CryptDecrypt` / `CryptDeriveKey` = **0**.
- Inlined crypto classes: `InvertibleRSAFunction` (x23), `Rijndael`/AES (x4).
- The embedded RSA-512 trust key is used to verify signed **SCE (Secure Crypto
  Element) plugin DLLs** (`sce*.dll`, entry `SceDllGetInfo1`) — a signed-code
  gate, not the device channel itself.

The presence of `InvertibleRSAFunction` (RSA with private-key capability) does not
imply a vendor secret: there is still **zero** embedded private-key material of any
kind, so any private-key RSA use is necessarily on an **ephemeral keypair the host
generates itself** at runtime (via `CryptGenRandom`). That needs no vendor secret.
The feasibility verdict stands.

## Roadmap to a working driver

1. Recover the frame-11 (crypto response) blob layout: how the 32-byte challenge,
   the fresh session key, and the RSA operation combine into the 96 bytes.
2. Recover the AES (Rijndael) session-key derivation and the channel framing/MAC.
3. Recover the post-session on-chip enrollment and verification command set.
4. Implement in a native `libfprint` driver using the match-on-chip
   (device-storage) API — the fingerprint image stays on the chip; the driver
   drives enroll/verify and reads back templates/results.

Steps 1-3 are careful decompiler work over the BSAPI module plus a few more
capture cycles against real hardware (the harness can act as an oracle, since the
device accepts or rejects each candidate response). No cryptographic barrier
remains between here and a working driver.

## The frame-11 crypto — fully reversed

Decompilation of the engine module (function at RVA `0x1d0ee0`) yields the exact
construction of the 96-byte crypto payload. It is **not** a single RSA block; it is
a hash + RSA composite:

```
payload (96 bytes) =
      SHA-256( ctr4 || challenge || Y )            # 32 bytes
   || RSA-512-PKCS1v15-encrypt( device_pubkey, session_key )   # 64 bytes
```

where
- `session_key` = 32 random bytes from the driver's SHA-based DRBG (seeded by
  `CryptGenRandom`).
- `device_pubkey` = the RSA-512 public key the device streams in handshake frame 6
  (the 64-byte value after `03 00 20 00 20 00`).
- `Y` = a 32-byte value fetched from the device with an internal command (`0x407`).
- `ctr4` = a 4-byte constant/counter prefix.
- RSA padding is **PKCS#1 v1.5 block type 2** (`00 02 <random non-zero> 00 <msg>`),
  confirmed in the padding routine (block type byte `2`, random `1..0xFF` filler,
  `00` separator, message right-aligned).
- Hash is **SHA-256** (32-byte output; the module's hash-type tag `0x12`).

The whole payload is sent as transceive command `0x308` (which is why the frame
command bytes read `08 03`). The device then replies, and the host **verifies** it by
recomputing `SHA-256( ctr4' || challenge || session_key )` and comparing to the
device's 32-byte answer — i.e. the device proves it decrypted the session key.

Object model note: the engine wraps primitives in tagged objects — tag `0x50` = the
RSA key/cipher, tags `0x11`/`0x12` = hash contexts. `RSAPublicKeyImpl` /
`RSAEncryptSink` do the public-key encryption; `Rijndael` (AES) carries the
post-handshake channel.

### Still to pin down (oracle-testable)

- RSA public exponent (`3` vs `65537`), and the byte order of the frame-6 modulus.
- The exact `ctr4` prefix bytes and the `0x407` `Y` value (or whether `Y` equals a
  value already seen earlier in the handshake).
- Session-key length (32 vs variable).

With the algorithm known and the device acting as an oracle (`tools/oracle.py`),
these are a bounded number of experiments rather than open research. No vendor
secret is involved at any step — only the device's own public key, a SHA-256, and
fresh randomness.

## Frame-11 exact recipe (dynamic instrumentation) + the remaining blocker

Hooking the vendor engine's SHA-256 init/update/final in a live handshake (Frida on
the WBF engine `svchost`, hooks at UPKBU RVAs `0x1ddbac`/`0x1ddbf0`/`0x1de990`) gives
the frame-11 authenticator byte-for-byte. Correlating with the USB capture, the
32-byte authenticator is:

```
auth32 = SHA-256( ctr4 || M || Y )
```
- `ctr4` = `e3 8f 7c b3` — a constant domain-separation tag (first byte matches the
  `0xe3` seen statically; verified identical across handshakes).
- `Y`   = the 32-byte reply to the `07 04` command (the device's per-session value).
- `M`   = a **32-byte long-term secret** (`94 1c f8 d6 …`), constant across handshakes,
  never transmitted, not derivable from any captured/handshake data.

The RSA half is `RSA-512-PKCS1v15-encrypt(device_pubkey, session_key)` where the
session key is **48 bytes** (`local_1d0 - 0x10`, not 32) of DRBG output. The 64-byte
device modulus arrives little-endian in frame 6.

`tools/frame11_build.py` synthesises a complete frame-11 from a live session using the
above and submits it to the device.

### SOLVED — the handshake completes from Linux

The rejection was **not** an `M` problem; `M` (`94 1c f8 d6 …`) is a persistent
device secret that survives a real USB reset. The bug was the RSA exponent.
Dumping the live RSA (Frida on the encrypt/padding/key-import routines) gave a
matched (padded-block, ciphertext, modulus) triple, solved offline:

```
n = int.from_bytes(device_key_64, "little")     # modulus is little-endian
e = 17    (0x11)                                 # NOT 3, NOT 65537
padding  = PKCS#1 v1.5 block type 2 (00 02 <13 random non-zero> 00 <48-byte key>)
ct = pow(int.from_bytes(block, "big"), 17, n).to_bytes(64, "big")
```

Full working frame-11:

```
payload(96) = SHA-256( ctr4=e38f7cb3 || M || Y ) || RSA(session_key)
```

Sent from Linux via `tools/oracle.py`, the device replies `08 13 20 00 00 00 …`
— **accept**. The advanced-mode cryptographic handshake is reproduced natively on
Linux with no vendor private key. `tools/oracle.py:build_response()` is the
verified implementation.

Remaining to a full driver: the AES session channel that follows frame-11, and the
on-chip enroll/verify command set. `M` is device-specific; deriving/establishing it
for an arbitrary unpaired sensor is a separate question, but for a sensor already
paired under Windows it is a fixed value that can be read once.

## Post-handshake: the AES session channel (next layer)

After frame-11 is accepted, the device sends its 32-byte confirmation
`SHA-256(bd30142a || M || session_key)` (verified against hardware), and a final
`00 80` exchange opens an encrypted channel that carries the on-chip enroll/verify
commands:

```
host -> Ciao ... 00 80 <16-byte AES block>
dev  -> Ciao ... 00 80 <longer AES payload>
```

The channel key derives from the 48-byte session key via the driver's SHA-256 KDF
(`SHA-256(62466e8d || Y || session_key || M)` is the leading candidate). Offline
analysis (every KDF hash output as an AES-128/192/256 key, across ECB/CBC/CFB/OFB/CTR
and several IVs) did **not** recover the plaintext, so the exact key/mode/IV needs the
same live-instrumentation treatment that cracked the RSA: hook the Rijndael block
operation in a running handshake to capture (key, plaintext, ciphertext) directly.
This is the next concrete task; there is no cryptographic uncertainty left, only the
channel's exact key schedule and framing.

## SOLVED — the AES session channel

Live instrumentation of the block cipher (the encrypt/decrypt routine, its round-key
buffer, and the key-schedule input) plus offline verification settle the channel:

- The channel cipher is **AES-128** (the T-table routine uses the standard AES
  decryption tables Td0-Td3 and the standard inverse S-box; a from-scratch equivalent
  inverse-cipher decryption with the captured round keys reproduces the plaintext
  byte-for-byte; standard `AES-128-ECB` with the recovered master key reproduces both
  directions).
- The **master key** is:

  ```
  aes_key = SHA-256( 62466e8d || Y || session_key || M )[:7]  +  b"\x00" * 9
  ```

  i.e. the first 7 bytes of that KDF output, right-padded with zeros to 16 bytes.
  Verified across independent sessions (the driver even runs the AES key schedule on
  this 7-non-zero-byte key).
- Blocks are processed with AES-128-ECB.

With the handshake accepted and this channel key, the driver can now encrypt/decrypt
the post-handshake `00 80` exchange and the on-chip command traffic. The only layer
left is the application protocol: the enroll and verify command set carried over this
AES channel, then wiring it into `libfprint`'s match-on-chip API. No cryptographic
unknowns remain.

## The application layer is now in the clear

With the AES channel key, the post-handshake command traffic decrypts to a
structured command protocol that mirrors the transport (`XX 04` request /
`XX 14` reply):

```
host -> device (decrypted):  00 00 0c 04 | 05 00 00 00 | <value> | 00 00 00 03
device -> host (decrypted):  00 00 0c 14 | 80 00 00 00 | 03 01 03 00 | 01 01 01 03 | <data blocks...>
```

Every byte of the session is now readable. What remains is purely the *application*
protocol — the specific command codes for enrollment and verification and the
device's result encoding — with **no cryptography left to break**. That, plus wiring
the result into `libfprint`'s match-on-chip (device-storage) API, completes a native
Linux driver.

## Summary of the cryptographic stack (all solved)

| Layer | Result |
|---|---|
| USB bring-up / mode switch | vendor control `40 0c` |
| Transport framing | "Ciao" + CRC-16/CCITT |
| Device authentication | host verifies device sig with embedded RSA-512 trust key |
| Handshake auth (frame-11) | `SHA-256(ctr4 ‖ M ‖ Y)` |
| Handshake key transport | `RSA-512-PKCS1v15(device_key, 48-byte session key)`, e=17 |
| Device confirmation | `SHA-256(bd30142a ‖ M ‖ session_key)` |
| Session channel | `AES-128-ECB`, key `SHA-256(62466e8d ‖ Y ‖ sk ‖ M)[:7]‖0×9` |

No vendor private key is used anywhere; every secret is either public (the device's
own key), the device's persistent `M`, or freshly generated randomness.
