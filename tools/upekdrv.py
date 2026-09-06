#!/usr/bin/env python3
"""upekdrv - a match-on-chip driver for the UPEK/AuthenTec TouchChip
(USB 147e:2020, "WBF advanced mode") on top of the reverse-engineered
transport + application-command channel in upek2020.py.

This is the driver API layer: open/close, device info, template store
enumeration, and the enroll / verify / identify / delete operations built
as explicit on-chip state machines. The crypto handshake, AES session
channel and SHA-token command envelope all live in upek2020.Upek and are
reused verbatim here.

Two things are runtime-unproven on this hardware and are isolated behind
clear seams so they can be swapped without touching the rest:

  * ARM_MODE - how the sensor is put into finger-scanning mode. Match-on-chip
    parts arm scanning one of two ways: a pure software prologue command
    ("soft"), or USB selective-suspend + remote-wakeup driven by the kernel
    ("suspend"). The latter cannot be done from libusb userspace. Select with
    the UPEK_ARM env var or the arm_mode= ctor arg.

  * ENROLL_SCANS - number of good captures the chip consolidates into one
    template. Overridable; default is the common UPEK value.

Everything else - transport, crypto, command set - is proven and shared with
upek2020.py.
"""
import os
import time
import upek2020 as u2

# --- device status codes (signed-16 reply word high half) ----------------------
# Populated from the RE of the capture state machine. RETRY_CODES already live
# in upek2020; extend the semantic map here as they are confirmed.
ST_OK          = 0        # operation/scan completed successfully
ST_NO_FINGER   = None     # placeholder: "no finger yet" -> use u2.RETRY_CODES
ST_NEED_MORE   = None     # placeholder: "good scan, need another"

# number of good captures consolidated into one enrolled template
DEFAULT_ENROLL_SCANS = 3


class EnrollResult:
    def __init__(self, template_id, scans, blob):
        self.template_id = template_id
        self.scans = scans
        self.blob = blob

    def __repr__(self):
        return f"<EnrollResult tpl={self.template_id} scans={self.scans} " \
               f"blob={len(self.blob) if self.blob else 0}B>"


class UpekDriver:
    """High-level driver. Wraps upek2020.Upek and exposes enroll/verify/etc."""

    def __init__(self, arm_mode=None, enroll_scans=DEFAULT_ENROLL_SCANS,
                 verbose=True):
        self.dev = None
        self.arm_mode = arm_mode or os.environ.get("UPEK_ARM", "soft")
        self.enroll_scans = enroll_scans
        self.verbose = verbose

    # -- lifecycle ---------------------------------------------------------------
    def open(self):
        self.dev = u2.Upek()
        self.dev.handshake()
        self._log("channel up")
        return self

    def close(self):
        if self.dev:
            try:
                self.dev.reset()
            except Exception:
                pass
            self.dev.close()
            self.dev = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *a):
        self.close()

    def _log(self, *a):
        if self.verbose:
            print(*a, flush=True)

    # -- introspection -----------------------------------------------------------
    def info(self):
        # get_info returns reply_body bytes (or None)
        return self.dev.get_info() or b""

    def identity(self):
        """The ASCII identity string the device reports in its status blob.
        The product string sits in the raw status blob past the declared reply
        length, so scan the whole block, not reply_body()."""
        dec = self.dev.get_status()          # raw reply block or None
        if not dec:
            return ""
        # longest run of printable ASCII = the product string
        best = cur = b""
        for c in dec:
            if 32 <= c < 127:
                cur += bytes([c])
                if len(cur) > len(best):
                    best = cur
            else:
                cur = b""
        return best.decode("ascii", "replace").strip()

    def caps(self):
        dec = self.dev.get_caps()
        return u2.reply_body(dec) if dec else b""

    def list_templates(self):
        r = self.dev.enum_templates()        # (len, body) or None
        if not r:
            return b""
        _, body = r
        return body

    def delete_template(self, tpl_id):
        body = int(tpl_id).to_bytes(4, "little")
        dec, _ = self.dev.call("del_tpl", body)
        return not u2.is_nak(dec)

    # -- sensor arming (the isolated, runtime-unproven seam) ---------------------
    def _arm_scanning(self, mode):
        """Put the sensor into finger-scanning mode. `mode` is 'enroll' or
        'verify'. Returns True if the arm command was accepted.

        arm_mode == 'soft'    : software prologue command (see _arm_soft).
        arm_mode == 'suspend' : USB selective-suspend + remote-wakeup. Not
                                achievable from libusb userspace; the driver
                                logs and returns False so the caller can bail
                                out to a kernel-assisted path.
        """
        if self.arm_mode == "suspend":
            self._log("arm_mode=suspend: sensor scanning requires kernel "
                      "selective-suspend + remote-wakeup, not doable from "
                      "userspace libusb. Falling back to poll-only.")
            return False
        return self._arm_soft(mode)

    def _arm_soft(self, mode):
        """Software prologue that arms the front-end for a capture poll.

        The exact prologue command (code + body) is being pinned from the
        decompiled capture state machine. Until confirmed, this issues the
        per-capture arm control kick (vendor 0x40 0x0c wIndex 0x0400) that the
        handshake also uses, which is the known-accepted front-end kick for
        this PID. Placeholder for a possible dedicated begin-op command.
        """
        try:
            self.dev.d.ctrl_transfer(0x40, 0x0c, 0x0100, 0x0400, b"\x00", 1000)
            return True
        except Exception as e:
            self._log("arm kick failed:", e)
            return False

    # -- capture -----------------------------------------------------------------
    def _capture_one(self, mode_word, timeout_s):
        """Poll the capture command until a finger is read or timeout.
        Returns (status, blob). status==ST_OK -> blob is the feature set."""
        deadline = time.time() + timeout_s
        polls = 0
        while time.time() < deadline:
            st, dec = self.dev.capture_once(mode=mode_word)
            polls += 1
            if st is None:
                time.sleep(0.15)
                continue
            if st in u2.RETRY_CODES:
                time.sleep(0.1)
                continue
            if st == ST_OK:
                return ST_OK, u2.reply_body(dec)
            # any other status -> report it up
            return st, u2.reply_body(dec)
        return None, None

    # -- enroll ------------------------------------------------------------------
    def enroll(self, mode_word=0x00040000, progress=None):
        """Run the on-chip enroll state machine: arm, then collect
        `enroll_scans` good captures, then consolidate into one stored
        template. Returns an EnrollResult, or None on failure/timeout.

        `progress(scan_index, total, status)` is called after each poll round.
        """
        if not self._arm_scanning("enroll"):
            self._log("enroll: sensor not armed (see arm_mode)")
            # continue anyway in poll-only mode; some parts scan without a
            # software arm once suspend PM is in place
        blobs = []
        obj_id = self._create_enroll_object()
        for i in range(self.enroll_scans):
            self._log(f"enroll scan {i+1}/{self.enroll_scans}: touch the sensor")
            st, blob = self._capture_one(mode_word, timeout_s=30.0)
            if progress:
                progress(i + 1, self.enroll_scans, st)
            if st != ST_OK or not blob:
                self._log(f"  scan {i+1} failed status={st}")
                return None
            blobs.append(blob)
            self._log(f"  scan {i+1} OK ({len(blob)}B)")
        tpl_id = self._consolidate(obj_id, blobs)
        return EnrollResult(tpl_id, len(blobs), b"".join(blobs))

    def _create_enroll_object(self):
        """create_obj (0x205) -> returns a u32 object id the scans attach to.
        Body/return shape from RE; treated as opaque here."""
        try:
            dec, _ = self.dev.call("create_obj", (0).to_bytes(2, "little"))
            body = u2.reply_body(dec)
            return int.from_bytes(body[:4], "little") if len(body) >= 4 else 0
        except Exception:
            return 0

    def _consolidate(self, obj_id, blobs):
        """consolidate (0x229): fold the collected feature sets into one
        on-chip template. Body = u32 obj_id, u32 count, <serialized sets>.
        Returns the new template id, or None."""
        body = int(obj_id).to_bytes(4, "little") + len(blobs).to_bytes(4, "little")
        for b in blobs:
            body += b
        dec, _ = self.dev.call("consolidate", body)
        if u2.is_nak(dec):
            return None
        rb = u2.reply_body(dec)
        return int.from_bytes(rb[:4], "little") if len(rb) >= 4 else None

    # -- verify / identify -------------------------------------------------------
    def verify(self, tpl_id, mode_word=0x00040000):
        """Capture a finger and match it against one template id.
        Returns True on match, False on no-match, None on failure."""
        if not self._arm_scanning("verify"):
            pass
        st, blob = self._capture_one(mode_word, timeout_s=30.0)
        if st != ST_OK or not blob:
            return None
        body = int(tpl_id).to_bytes(4, "little") + blob
        dec, _ = self.dev.call("match_tpl", body)
        if u2.is_nak(dec):
            return None
        return u2.status16(dec) == ST_OK

    def identify(self, mode_word=0x00040000):
        """Capture a finger and identify against the whole on-chip DB.
        Returns matched template id, or None."""
        if not self._arm_scanning("verify"):
            pass
        st, blob = self._capture_one(mode_word, timeout_s=30.0)
        if st != ST_OK or not blob:
            return None
        dec, _ = self.dev.call("identify", blob)
        if u2.is_nak(dec) or u2.status16(dec) != ST_OK:
            return None
        rb = u2.reply_body(dec)
        return int.from_bytes(rb[:4], "little") if len(rb) >= 4 else None


def main():
    import sys
    op = sys.argv[1] if len(sys.argv) > 1 else "info"
    drv = UpekDriver()
    drv.open()
    try:
        print("identity:", drv.identity())
        print("templates:", drv.list_templates().hex())
        if op == "enroll":
            r = drv.enroll()
            print("enroll ->", r)
        elif op == "verify":
            tpl = int(sys.argv[2]) if len(sys.argv) > 2 else 0
            print("verify ->", drv.verify(tpl))
        elif op == "identify":
            print("identify ->", drv.identify())
    finally:
        drv.close()


if __name__ == "__main__":
    main()
