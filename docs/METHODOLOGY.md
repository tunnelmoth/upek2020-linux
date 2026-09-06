# Methodology

Everything here was produced from a device physically owned by the author.

## USB capture

The vendor driver only exists for Windows, so the reference traffic was captured
by running the signed AuthenTec driver inside a Windows VM with the USB device
passed through, and sniffing the host-side USB bus with `usbmon` + `tcpdump`.
`tools/usbpcap.py` decodes the resulting `usbmon` pcaps (linktype 220).

Two independent handshake captures were compared frame-by-frame to separate the
static protocol prefix from the per-session cryptographic block.

## Static reversing

The two driver modules were analysed with Ghidra (headless). The feasibility
conclusion rests only on:

- the modules' **import tables** (which CryptoAPI functions are called), and
- a byte scan for embedded key blobs (`RSA1`/`RSA2`, PKCS#1/#8).

No decompiled vendor code is redistributed here; the repository contains only
independently-authored code and the author's own protocol notes.

## Live validation

`tools/harness.py` reproduces the bring-up and transport on Linux via `libusb`,
confirming the reversed sequence against the real hardware and capturing a live
challenge. The device's responses match the Windows capture byte-for-byte through
the static prefix.

## Reproducing

1. Windows VM (e.g. QEMU/KVM) with the `147e:2020` device passed through and the
   official AuthenTec "TouchChip Fingerprint Coprocessor (WBF advanced mode)"
   driver installed.
2. `modprobe usbmon`; `tcpdump -i usbmon<N> -w handshake.pcap`.
3. Trigger the biometric service (it performs the handshake on start).
4. Decode with `tools/usbpcap.py handshake.pcap <devnum>`.
5. Drive the device natively with `tools/harness.py`.
