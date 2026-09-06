# Application command layer (147e:2020, WBF advanced mode)

Once the AES-128-CBC session channel is up (see `CRYPTO.md`), the host and device
exchange **application commands** inside the encrypted `0x0080` data frames. This
document describes that layer. Everything here is verified against real hardware
(ThinkPad W530, module `Lenovo TCD51-TCS5D POA`).

## Command envelope (the integrity token)

Every application command is a plaintext block, AES-CBC-encrypted as the payload of
a `0x0080` transport frame. The block is:

```
code_word(4)  = ((code & 0xfff) << 16)  as little-endian u32
body(N)       = command-specific parameters
token(4)      = SHA-256(code_word || body)[0:4]
padding       = zero bytes up to enc_len = (24 + N) & ~15,
                with the LAST pad byte overwritten to (enc_len - N - 9)
```

The `token` is an **unkeyed, truncated SHA-256** over `code_word || body`. The
device recomputes it and rejects any command whose token does not match, returning
a fixed NAK block:

```
35 f6 f0 1f 4e d7 0f 4b 00 00 00 00 00 00 00 07
```

There is **no session-key material** in the token — it is pure SHA-256 of the
command bytes — so a captured command replays across sessions. This is the single
fact that unlocks the whole command set: with the token computed per command, every
`0x2xx`/`0x4xx` application command becomes available. (Historically this looked
like a "secure mode" gate, and on Windows presented as the biometric unit failing
to come online with `NOT_SUPPORTED`; the real cause was simply the per-command
token.)

`tools/upek2020.py:appcmd(code, body)` builds this block.

### Worked example — `get_info` (code 0x40c, body = u32 info-type 5)

```
code_word = 00 00 0c 04
body      = 05 00 00 00
token     = SHA-256(00 00 0c 04 05 00 00 00)[0:4] = 44 6f ce f0
enc_len   = (24 + 4) & ~15 = 16 ; pad = 4 bytes, marker = 16-4-9 = 3
block     = 00 00 0c 04 | 05 00 00 00 | 44 6f ce f0 | 00 00 00 03
```

Device reply (plaintext, inside its own `0x0080` frame):

```
00 00 0c 14 | 80 00 00 00 | <128 bytes of sensor params>
```

i.e. `reply_word = code_word | 0x10000000`, then `u32 length`, then the payload.

## Reply format and status

A reply block begins with a 16-bit **status** (low half of the reply word) and a
16-bit code echo (high half of the low 32 bits), then a `u32 length`, then data:

```
[s16 status][u16 code_echo][u32 length][payload...]
```

- `status == 0` : success, `payload` is the result.
- `status < 0`  : device status code. Known values:

| status | hex | meaning |
|---|---|---|
| -0x427 | 0xfbd9 | no finger present (capture) / no data — **retry** |
| -0x426 | 0xfbda | swipe not complete / aborted — retry |
| -0x41a | 0xfbe6 | intermediate touch / timeout — retry |
| -0x419 | 0xfbe7 | busy / bad state |

`tools/upek2020.py:status16()` / `reply_body()` decode these.

## Command map

Codes confirmed to respond on hardware. Body layouts from `upkbu.dll` RE.

| name | code | body | reply |
|---|---|---|---|
| get_info | 0x40c | u32 info-type (1,3,4,5 valid) | [u32 len][sensor params] |
| get_caps | 0x406 | empty | capability struct |
| get_status | 0x411 | empty | status struct (contains product string) |
| get_prop32 | 0x403 | u32 id | u32 |
| set_prop | 0x40b | [u16 id][u16 len][data] | — |
| enum_tpl | 0x20d | empty | count + on-chip template records |
| db_desc | 0x250 | — | storage descriptor |
| get_list | 0x215 | empty | list/status blob |
| reset | 0x207 | empty | — (abort current op) |
| **capture** | **0x20e** | mode(u32)+subop(u8)+flags(u16) | template/feature blob, or no-finger status |
| stream_cap | 0x216 | same as capture | async streaming (callback transport) |
| create_obj | 0x205 | u16 | u32 object id |
| consolidate | 0x229 | u32,u32,\<serialized features\> | [u32 result][u32 value] |
| match_tpl | 0x209 | template obj + sample | [u32 result(0=no match)][id][score] |
| identify | 0x20a | — (on-chip DB) | s32 index (-1 = no match) |
| del_tpl | 0x212 | u32 id | — |

## Capture (0x20e)

Match-on-chip: no raw image crosses USB. Capture is a synchronous poll.

```
body = mode(u32) + subop(u8=0) + flags(u16=0x0001)   # flag bit0 = capture-enable
```

- `mode` is a time/frame budget. Small values return quickly; `0x7fffffff` waits.
- Poll `0x20e` in a loop. While no finger, status is -0x427 / -0x426 / -0x41a.
- When a finger is read, status is `0` and the reply body carries the feature/
  template blob (record format selected by `subop`).

`tools/upek2020.py:capture()` implements the poll loop.

## Enroll / verify (state machine, from RE — live validation pending)

- **Enroll**: default 5 good captures (`bioConsolidationCount`, clamped to {1,3,5}),
  then `0x229` consolidate to build the on-chip template, then a store/object op
  (`0x461`/`0x456`) returns a 0x50-byte template descriptor (leading u32 = on-chip
  slot id). The host persists `(WinBioAdapterTemplateId, FingerIndex, user)`.
- **Verify**: one capture (`0x20e`), then match on chip — `0x209` against a specific
  template (reply u32 result, 0 = no match, else id+score) or `0x20a`/`0x229`
  identify against the whole on-chip DB (s32 index, -1 = no match).

Templates are referenced on the wire as a tagged object:
`03 00 00 00 <u32 len> <bytes>` (blob) or `80 00 00 00 <u32 id>` (slot id).

## Async operations & transport class (partial — capture blocker)

Simple commands (info/caps/status/enumerate/config) are synchronous and use
transport-frame byte **b6=0x17**. The capture/enroll/verify **operations**
(0x20e/0x208/0x216 grab, 0x220/0x21c begin-operation, 0x212/0x201 control) are
driven by an asynchronous, callback-based transport and need a **different b6**.

Verified on hardware: `0x220 begin-operation` sent with b6=0x17 makes the device
answer with a short control frame `Ciao 02 00 02 92 <b> + crc16` (b7=0x92) instead
of a normal reply; sent with **b6=0x27** it returns a normal encrypted reply. So
the transport class is encoded in b6.

Async command word (first 4 bytes of the decrypted app block, LE u32):
`nibble(31..28) | opcode(27..16) | status(15..0)`. Nibble `2` = notification (host
must send a `0x30000000` continuation), `8` = image/data body, `3` = host
continuation, else = terminal reply (status = low 16 bits, signed).

**Open blocker:** the begin-operation (0x220) exact `verb` + descriptor and the
0x212/0x211 `opcode` are held in the driver's C++ `Bio::Pt::GrabberImpl` layer
behind `.rdata` factory vtables (`FUN_1801c8328`, classids 0x64..0x3e9). Without
the right operation handle from a successful begin-operation, every grab returns
-0x427 (engine not armed) and every control command returns -0x21 (bad param).
This is the one remaining piece before a live fingerprint capture.

## Low-level "type-nibble" transport (operation layer)

The capture/scan OPERATION does not use the AES command channel. It uses a second,
lower framing over the same bulk endpoints (`tools/lowlevel.py`):

```
"Ciao" | hdr0 hdr1 hdr2 | payload | crc16
  hdr0 = frame TYPE (low nibble)
  hdr1 = seq(7:4) | length[10:8](2:0)
  hdr2 = length[7:0]
  crc16 = CRC-16/CCITT, little-endian, over hdr0..payload
```

Frame types: 0=DATA, 1=IDLE, 2=STATUS/ERROR(s16 code), 3=READY, 4=host-DATA,
5=RESULT, 6=host START, 7=host ABORT, 8=BUSY, 9/10=keep-alive(no-finger/finger),
0xb=EVENT. The AES and low-level framings must not be interleaved — mixing
corrupts state.

Verified handshake (device is the oracle; CRCs match byte-for-byte):

```
type-7 abort  4369616f 070001 00 1c62   -> device type-1 idle
type-6 start  4369616f 060000    a0b2   -> device type-3 ready, payload 01000000c0
type-4 data   [01][00][u32 timeout][u16 maxframe][echo type-3 payload]
                                          -> device type-5 result, payload 00 (success)
```

**Open limit:** this type-6/4/5 exchange (on-chip SM `FUN_1801e03c0`) returns
success regardless of finger state and delivers no image. The raw-image streaming
SM (`FUN_1801e12a4`/`FUN_1801e07d8`, type-0 DATA + type-8/9/10 poll) is selected by
higher-layer Grabber config, and the actual sensor read is a transport-object
callback (vtable +0x38) implemented in the lower USB/WinUSB function driver, which
is not part of the decompiled `upkbu.dll`/`tcwbf.dll`. Reconstructing the final
scan trigger therefore needs a low-level usbmon capture of the Windows driver, not
just these DLLs.

## Advanced DES image-cipher handshake (spec, not yet exercised)

Image-data frames (AES-channel command-word nibble 8) are DES-encrypted with a key
installed by an advanced key-negotiation that a plain (basic) session skips:

1. `0x407` get 8 random bytes `R_dev`.
2. `R_host` = 8 random bytes; `des_key = 37 EA 23 CE D3 40 C4 AE` (embedded in the DLL).
3. `0x408` body = `DES-CBC(des_key, IV=R_dev, PKCS7( R_host(8) || le32(0) || 8×00 ))`
   (24 bytes). Device echoes `R_dev` in the reply on success.
4. `pre_key = KDF(R_dev, R_host, des_key)` — SHA-1 rounds over
   `prev20 || R_dev || R_host || des_key`, take digest bytes [3,7,11,15] per round,
   reversed fill, 32 bytes; `data_key = odd_parity(pre_key[:8])`.
5. `0x416` body = `le32(0x21) || le32(0x38) || le32(0) || le32(3)` — installs the DES
   image cipher at deviceObj+0x2a0; the AES command channel is untouched.
6. Image frames then decrypt with `DES-CBC(data_key, IV=0)`, IV chained across frames.

The command channel stays AES-128-CBC; DES applies only to bulk image frames.

## Capture architecture — the full object stack (from RE)

The physical scan and image delivery are split across the two DLLs and a lower
WUDF/UMDF driver:

- `deviceObj` (magic `'LhDd'`, upkbu) = the type-nibble protocol engine. Field
  `+0x88` = operation MODE (0/0xff = on-chip TYPE-6/4/5 path; 1/2 = raw-image
  streaming). `+0x24` = session-armed, `+0x84` = streaming-enabled, `+0xb4` = TYPE-0
  seq counter.
- `transportObj` = `*(deviceObj+8)` (magic `'SIfc'`, tcwbf) — its vtable slots are
  the hardware ops: +0x38 finger-sense (a `WaitForMultipleObjects` on Win32 events,
  NOT a wire frame), +0x40 TYPE-4 challenge buffer, +0x58/+0x60 USB read/write,
  +0x80 arm (sensor register cmd 2), +0x88 LED (register cmd 1).
- `'SuTr'` USB transport (tcwbf) — spawns a background overlapped bulk-read thread
  that pushes TYPE-0/TYPE-0x0b image frames and signals a finger-ready event. This
  thread + the raw pipe I/O are the ONLY piece not in the DLLs (it lives in the
  lower WUDF driver, reached via a `DP%08X` COM property store + DeviceIoControl
  IOCTLs 0x350c060/0x350c064). Driving EP 0x02/0x81 directly REPLACES this module.

### Why TYPE-6/4/5 never yields pixels

TYPE-6/4/5 is the on-chip (template-domain) match/enroll path. The image is
consumed on-chip; TYPE-5 `00` just means "on-chip op done". No pixels cross it.
The TYPE-3 payload `01 00 00 00 c0` sets bit31 ("host must append a challenge
response to TYPE-4"); the `+0x40` callback returns a pre-registered crypto blob,
not scan params — so no TYPE-4 content makes it scan.

### The raw-image path (what actually captures)

1. Sensor ARM = sensor-REGISTER writes (finger-detect enable, bias, scan enable,
   LED) via the tcwbf register map (`FUN_180090728`/`FUN_180090c6c`), plus an
   `'MVNS'` (0x534e564d) NV/config load — all carried as commands over the bulk
   channel the host already drives.
2. Then the firmware pushes image lines as TYPE-0 / TYPE-0x0b frames; TYPE-8 = busy
   (answer TYPE-9/10 keepalive). Host reads EP 0x81 continuously.

The remaining work to capture from Linux is to replicate the sensor-register arm
sequence (addresses/values are sensor-descriptor data in tcwbf) and pump the TYPE-0
channel. Interrupt EP 0x83 is unused for image data in the stock driver (it polls
bulk), so its silence is expected.

## Raw-image scan trigger (the capture mechanism)

The raw fingerprint image is NOT started by any "Ciao" command or the on-chip
TYPE-6/4/5 path. It is a **vendor control transfer**, the same `bRequest=0x0c` used
for the mode-switch, with a different `wIndex`:

```
mode-switch / command-mode kick :  40 0c  wValue=0100 wIndex=0400  data=00
START raw scan                  :  40 0c  wValue=0100 wIndex=0601  data=00
STOP  raw scan                  :  40 0c  wValue=0100 wIndex=0602  data=00
```

After START, the sensor front-end is armed (the firmware handles the analog
front-end for PID 0x2020; the legacy per-register writes are dormant), and image
lines stream as "Ciao" **type-0 DATA** frames on bulk EP 0x81 while a finger is on
the sensor. The Ciao read path does not decrypt, so plaintext pixels arrive as-is.
Sensor format is 8-bit grayscale, up to 508x508 at 508 dpi (format table indexes
508x508 / 381x381 / 508x254 / 254x254 at 1/4/8 bpp).

`tools/upek2020.py:scan_start()` / `scan_stop()` / `capture_image()` implement this.

Verified: the `0x0601` control transfer is accepted by the device from Linux after
the handshake. Live pixel capture is pending a physical swipe (a swipe sensor emits
no data without a finger, so the bulk pipe is silent until a finger moves across).
`'MVNS'` is a host-side property store, not a device command; and the Windows-init
class requests (recipient OTHER, wIndex 3) that the stock driver issues stall on
Linux but are not required for the scan trigger.

## Finger-detect / capture (definitive — the unresolved layer)

Ground-truth correction from usbmon captures of the stock Windows driver (device
147e:2020 in a passthrough VM):

- **This PID is match-on-chip ONLY.** The raw-image path (`RawGrabber`, opcode
  0x601, EP 0x81 pixel frames) is never bound for product code 0x602/0x702; low
  byte 0x02 fails the `&5` RAW_IO gate. No pixels ever cross USB. The device does
  on-chip enroll/verify/match; the real per-swipe data (when it exists) rides the
  encrypted Ciao channel command responses, not any pixel stream.
- The vendor status byte6 (`C0 04` reply) is a readiness *hint* (0x00 fresh, 0x07
  after a clean re-enumeration), NOT a gate — captures happen at both values.
- Front-end sensor-register writes (`40 0C wValue=0x0000 wIndex=<reg>`) are
  host-side shadowed for this PID and never reach the bus — not a usable arm.
- The per-capture arm is `40 0C wValue=0x0100 wIndex=0x0400`; the low-level
  type-6/3/4/5 exchange is a once-per-session channel OPEN (type-3 payload is the
  constant `01 00 00 00 c0` hello, never a finger frame).
- **The finger detector is gated by USB selective-suspend + remote-wakeup**, set
  by the WinUSB power policy `SetPowerPolicy(AUTO_SUSPEND=0x81, 1)` — a
  host-stack/power-management action with NO packet on the wire. The chip's
  hardware finger-detect only powers up while the device is suspend-capable and
  reports a finger via USB remote wakeup / the interrupt endpoint status
  (bit0-inverted).

Implemented from Linux (device autosuspended, `power/wakeup=enabled`,
`SET_FEATURE(DEVICE_REMOTE_WAKEUP)`, armed with `40 0C 0x0400`), a finger touch
produced NO remote wakeup (dmesg shows none) and no status change. So the
finger-detect does not trigger from a libusb userspace driver — it appears to
need proper kernel-driver power management (and possibly the interrupt-endpoint
wakeup source armed the way WinUSB does).

**No ground truth of a successful capture exists**: every Windows enroll capture
in hand aborts right after the crypto handshake (the WBF biometric unit never
onlined — "secure component NOT_SUPPORTED" in the VM), so the sensor never
actually scanned a finger, on Windows or Linux, in this setup.

Bottom line: the entire crypto/transport/command protocol is reversed and works;
the remaining blocker is the sensor's finger-detect, a driver-level USB
power-management mechanism with no on-wire packet, for which there is also no
working capture to replicate. A real driver (libfprint / kernel module)
implementing the reversed protocol plus the suspend/remote-wakeup power policy is
the path to a live capture.
