# Protocol: USB transport and handshake

## Device

- USB `147e:2020`, interface class `0xff` (vendor), one interface.
- Endpoints: `0x81` bulk IN, `0x02` bulk OUT, `0x83` interrupt IN (4-byte).
- Descriptor advertises "advanced mode" (3 endpoints) once enumerated.

## Bring-up

The bulk pipes are inert until a vendor control "mode switch". The exact Windows
sequence, reproduced verbatim:

```
GET_DESCRIPTOR (device, config, strings)          # standard enumeration
CTRL IN   bmReq=0xc0 bReq=0x04 wVal=0 wIdx=0 len=8 # vendor read, x2, returns 8 bytes
CTRL OUT  bmReq=0x40 bReq=0x0c wVal=0x0100 wIdx=0x0400 len=1 data=0x00   # MODE SWITCH
```

Gotchas on Linux:
- The device wedges if a previous session was interrupted; force a clean
  re-enumeration (sysfs `unbind`/`bind`).
- Do **not** call `SET_CONFIGURATION` again after the kernel has selected config 1.
  Re-selecting the configuration resets the state that makes the mode switch valid,
  and every subsequent bulk write then times out.

## "Ciao" transport framing

After the mode switch, host and device exchange length-delimited frames on the
bulk pipes. Frame layout:

```
"Ciao" (0x43 0x69 0x61 0x6f) | seq(1) | sub(1) | b6(1) | 0x28 | len32(LE) | payload | crc16
```

- `sub` increases by 0x10 per command pair within the crypto sub-session
  (0x00, 0x10, 0x20, 0x30, 0x40, 0x50).
- `0x28` is a constant tag.
- Responses larger than 64 bytes span multiple bulk packets; concatenate reads.

## Handshake sequence

Directions are H→D (host to device) and D→H. All frames below except the crypto
block are byte-for-byte identical across sessions (static); the crypto block is
per-session.

| # | dir | command | meaning |
|---|-----|---------|---------|
| 0 | D→H | `Ciao 03 00 05 01 …` | device hello / capabilities (`c0 69 f8`) |
| 1 | H→D | `Ciao 04 00 08 01 …` | host hello |
| 2 | D→H | `Ciao 05 00 01 01 55 9f` | ack |
| 3 | H→D | `… 06 04` | get_info |
| 4 | D→H | `… 06 14 55 02 01 05 …` | info (firmware/version `05 02 01 05`, sensor geometry) |
| 5 | H→D | `… 02 04 0b` | read object 02 |
| 6 | D→H | `… 02 14 … 03 00 20 00 20 00 <64B>` | **device static public key material** (RSA-512) |
| 7 | H→D | `… 51 04 0a` | read object 51 |
| 8 | D→H | `… 51 14 …` | object 51 |
| 9 | H→D | `… 07 04 20` | request 32-byte challenge |
| 10 | D→H | `… 07 14 <32B>` | **per-session challenge** (differs every run) |
| 11 | H→D | `… 08 03 01 … 60 00 00 00 <96B>` | **host crypto response** (challenge-bound) |
| 12 | D→H | `… 08 13 20 00 00 00 <32B>` | device accepts (short `08 13 …` with error code = reject) |
| 13 | H→D | `… 00 80 <20B>` | session confirm |
| 14 | D→H | `… 00 80 <encrypted>` | encrypted session established |
| … | | | AES channel; on-chip enroll / match |

The determinism split (frames 0-9 static, 10-14 per-session) was verified by
diffing two fresh captures. Replaying frame 11 from a different session's challenge
makes the device return the short `08 13` error — i.e. the 96-byte response is
cryptographically bound to the live challenge.

## Frame sizes of interest

- Challenge: 32 bytes.
- Host crypto response: 96 bytes (`0x60`), preceded by length fields `0x31`, `0x38`.
- Device static key material: 64 bytes = RSA-512 modulus.
- Embedded trust key: RSA-512.


## Frame CRC (solved)

The 2-byte trailer is **CRC-16/CCITT**: polynomial `0x1021`, init `0x0000`, no
input/output reflection, no final XOR. It is computed over the frame **after** the
4-byte `Ciao` magic, up to (but not including) the trailer, and stored
**little-endian**. The 32-bit length field counts the content **plus** the 2 CRC
bytes. `tools/oracle.py:build_frame()` reproduces every captured frame, including
the 144-byte crypto frame, byte-for-byte.

```
frame = "Ciao" | seq | sub | b6 | 0x28 | len32_LE | content | crc16_LE
crc16   = CRC-16/CCITT(seq .. end-of-content)
len32   = len(content) + 2
```

With this, the entire transport is reproducible from Linux. The only remaining
unknown for a completed handshake is the 96-byte crypto payload inside frame 11.
