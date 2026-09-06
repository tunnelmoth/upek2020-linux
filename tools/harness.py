#!/usr/bin/env python3
"""
Raw-USB harness for the UPEK/AuthenTec TouchChip Fingerprint Coprocessor
"WBF advanced mode" (USB 147e:2020) on Linux.

Reproduces the Windows driver's init + "Ciao" transport handshake up to the
per-session cryptographic challenge, entirely from user space via libusb.
Read-only exploration tool; it does not enroll or match.

Requires: python3-usb (pyusb), libusb-1.0, root (for USB claim + sysfs rebind).

The device wedges easily if a prior session was interrupted, so we force a
clean re-enumeration via sysfs unbind/bind, and we DO NOT call
set_configuration() afterwards (the kernel already selected config 1; issuing
SET_CONFIGURATION again resets the device state that makes the mode-switch valid).
"""
import sys, time, os, glob
import usb.core, usb.util

VID, PID = 0x147e, 0x2020
EP_IN, EP_OUT, EP_INT = 0x81, 0x02, 0x83

def sysfs_dev():
    for vp in glob.glob("/sys/bus/usb/devices/*/idVendor"):
        base = os.path.dirname(vp)
        if open(vp).read().strip() == "147e" and \
           open(base + "/idProduct").read().strip() == "2020":
            return os.path.basename(base)
    return None

def rebind():
    d = sysfs_dev()
    if not d:
        sys.exit("device 147e:2020 not found")
    open("/sys/bus/usb/drivers/usb/unbind", "w").write(d); time.sleep(0.5)
    open("/sys/bus/usb/drivers/usb/bind", "w").write(d);   time.sleep(1.5)

# --- "Ciao" transport frames captured from the Windows driver (static prefix) ---
# Frame layout: "Ciao"(0x6f616943) | seq | sub | b6 | 0x28 | len32(LE) | payload | crc16
HOST_HELLO = "4369616f04000801005e01000000000d65"
GET_INFO   = "4369616f00000728040000000604c0d6"
CMD_02     = "4369616f00100b280800000002040b0000006556"
CMD_51     = "4369616f00200b280800000051040a00000079a5"
CMD_07     = "4369616f00300b28080000000704200000005d11"   # -> device returns 32-byte challenge

def main():
    rebind()
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    usb.util.claim_interface(dev, 0)

    def rd(t=800):
        try: return bytes(dev.read(EP_IN, 512, t))
        except usb.core.USBError: return None
    def drain(n=8, t=600):
        out = []
        for _ in range(n):
            r = rd(t)
            if r is None: break
            out.append(r)
        return out
    def wr(h): dev.write(EP_OUT, bytes.fromhex(h.replace(" ", "")), 1000)

    # Windows control prelude, then mode switch (activates the bulk pipes).
    dev.ctrl_transfer(0xc0, 0x04, 0x0000, 0x0000, 8, 1000)
    dev.ctrl_transfer(0xc0, 0x04, 0x0000, 0x0000, 8, 1000)
    dev.ctrl_transfer(0x40, 0x0c, 0x0100, 0x0400, b"\x00", 1000)   # MODE SWITCH
    print("[+] mode switch issued")

    hello = drain(2, 500)
    for h in hello:
        print("    device hello:", h.hex())

    for label, frame in [("host_hello", HOST_HELLO), ("get_info", GET_INFO),
                         ("cmd_02", CMD_02), ("cmd_51", CMD_51), ("cmd_07", CMD_07)]:
        wr(frame); time.sleep(0.03)
        resp = b"".join(drain(6, 600))
        print(f"[>] {label:10} -> {resp.hex() or '(none)'}")
        if label == "cmd_07" and resp:
            # payload after 'Ciao 00 30 27 28 24000000 0714' is the 32-byte challenge
            i = resp.find(bytes.fromhex("0714"))
            if i >= 0:
                print("\n[*] LIVE 32-byte challenge:", resp[i+2:i+2+32].hex())

    usb.util.release_interface(dev, 0)

if __name__ == "__main__":
    main()
