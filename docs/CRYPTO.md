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
