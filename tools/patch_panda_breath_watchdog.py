#!/usr/bin/env python3
"""Patch a Panda Breath firmware to add a device-side comms-loss heater watchdog.

WHAT IT DOES
    The stock BIQU Panda Breath is an autonomous WiFi heater: once told to heat,
    it holds that state on its own. If the controlling host (printer/broker)
    disappears mid-heat, nothing on the network can turn it off, so the chamber
    keeps heating to its last setpoint until connectivity returns. This patch
    closes that gap *on the device*: if the Panda loses BOTH its broker link and
    its printer link for 5 minutes while heating, its own firmware turns the
    heater off. When a link returns, the host re-commands heat as normal.

    Nothing else changes: the hardware over-temperature cutoff (~105 C) and the
    normal thermostat are untouched, and while any control link is up the patch
    is transparent.

HOW IT WORKS (see the reverse-engineering notes at the bottom of this file)
    The firmware's heater control task calls a one-line "is heating enabled?"
    getter every ~500 ms. We redirect that single call to a ~90-byte trampoline
    (hosted in the space of a dormant, cold-sensor-only 60 s timer we retire),
    which each pass:
      * reads the two connection-state globals (broker + printer);
      * if EITHER reads CONNECTED, refreshes a "last seen" timestamp
        (reusing esp_timer_get_time exactly as the retired timer did);
      * else if >5 min elapsed, clears the heat-enable byte so the control loop
        shuts the relay off on its next pass;
      * returns the enable byte (drop-in for the getter it replaced).
    Three same-length, in-place edits; esptool re-computes the image checksum +
    SHA-256 on save, so the output is a flashable, valid image.

SAFETY TRADE-OFF (removed feature)
    The trampoline is hosted in a function that implemented a ~60 s
    "max continuous ON" cap, but that cap was only ever *invoked* in a
    cold-sensor regime (chamber AND limit reading < 16 C) and was dormant during
    all normal heating. It is retired here. The primary over-temp check, the
    thermistor-fault shutdown path, and the hardware ~105 C cutoff all remain,
    and this watchdog is a broader, always-relevant safety in its place.

VERSION SUPPORT / SAFETY GATE (fail-closed)
    Unlike the same-length string swaps in patch_panda_breath_70c.py, this patch
    injects code that references absolute per-build addresses (the connection
    globals, esp_timer, the enable byte). A wrong address would brick the device,
    so the gate is fail-closed and independently auditable:

      1. PRIMARY: a SHA-256 allowlist of the *parsed* app image (see
         ACCEPTED_FINGERPRINTS). The hash decides accept/reject. It is taken over
         the parsed image (entry + segments), not the raw dump, so trailing 0xff
         partition padding or the appended integrity hash can't change it.
      2. SECONDARY: the sites are located by code signature and the original
         bytes are verified before patching. An image is NEVER accepted merely
         because the instruction patterns happen to occur — the hash must match.

    On rejection the tool prints the detected fingerprint, writes NO output, and
    explains that the build must be manually analysed first.

    Accepted builds (published fingerprints; publishing hashes does not
    distribute proprietary firmware):
      e178ad73…49affbd  Panda Breath v1.0.4 (ESP-IDF 5.1.4), untouched
      cf7a56dd…d968e94  Panda Breath v1.0.4, 70 C-patched
    Validated on hardware: BIQU Panda Breath ESP32-C3, app compile "May 28 2026".
    Works on the stock image or one already 70 C-patched (different regions).
    To add a build: re-derive the addresses/signatures (notes at end), validate
    on hardware, and add its fingerprint to ACCEPTED_FINGERPRINTS.

USAGE
    python3 patch_panda_breath_watchdog.py <stock_or_70c.bin> <patched.bin>

    Flash the app slot only (do NOT touch the bootloader), e.g.:
    esptool.py --chip esp32c3 -p /dev/ttyUSB0 write_flash <app_offset> <patched.bin>
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from esptool.bin_image import LoadFirmwareImage

# ── PRIMARY GATE: fail-closed SHA-256 allowlist of accepted app images ────────
# The fingerprint is taken over the *parsed* ESP application image (entry point +
# each loadable segment's load address, length, and data) — NOT the raw
# app-partition dump — so variable trailing 0xff padding, or the image's own
# appended integrity hash, cannot change it. Publishing these hashes does not
# distribute the proprietary firmware.
#
# The hash decides accept/reject. The code signatures further below are only a
# second validation layer; an image is NEVER accepted merely because the
# expected instruction patterns happen to occur.
#
# To support a new build: obtain its OEM image, re-derive the addresses and
# signatures (see the notes at the end of this file), validate on hardware, then
# add its fingerprint here with a description.
FP_DOMAIN = b"panda-breath-appimg-v1"
ACCEPTED_FINGERPRINTS = {
    "e178ad733456117d6471947d4c449e8f0b14c94f3e80f3c71be9d4a4a49affbd":
        "Panda Breath ESP32-C3 app v1.0.4 (ESP-IDF 5.1.4, compile May 28 2026), untouched",
    "cf7a56dd6bd5aa86eff66bbf45613dee2c2e317df4c88826183ed68ead968e94":
        "Panda Breath ESP32-C3 app v1.0.4, 70C-patched (patch_panda_breath_70c.py)",
}


def image_fingerprint(img) -> str:
    """Canonical SHA-256 of the parsed app image (dump-padding independent)."""
    h = hashlib.sha256()
    h.update(FP_DOMAIN)
    h.update(int(img.entrypoint).to_bytes(4, "little"))
    for seg in sorted(img.segments, key=lambda s: s.addr):
        h.update(int(seg.addr).to_bytes(4, "little"))
        h.update(len(bytes(seg.data)).to_bytes(4, "little"))
        h.update(bytes(seg.data))
    return h.hexdigest()


# ── Validated build fingerprint (all addresses are true runtime vaddrs) ───────
IROM_LOAD = 0x42000020            # IROM segment load address

# Site vaddrs within the validated build:
HOST_VADDR = 0x4200D2BC           # retired 60 s timer -> trampoline lives here
REDIRECT_VADDR = 0x4200D438       # the loop's `jal ra, <enable-getter>` we redirect
NOP_VADDR = 0x4200D4E0            # the loop's call to the retired timer we NOP out
GETTER_VADDR = 0x4200E5D4         # the enable-getter (returns *0x3fc9cae0)

# Code signatures (bytes as they appear in the IROM segment data):
HOST_SIG = bytes.fromhex("b7d7c93f83c727ac")        # lui x15,0x3fc9d; lbu x15,-1342(x15)
GETTER_SIG = bytes.fromhex("b7d7c93f03c507ae8280")  # lui x15,0x3fc9d; lbu x10,-1312(x15); ret
ANCHOR_EA5F = bytes.fromhex("1307f7a5")             # addi x14,x14,-1441 (0xea5f, the old 60 s threshold)

# Original 4 bytes expected at each edit site (little-endian instruction words):
ORIG_HOST = bytes.fromhex("b7d7c93f")   # lui x15,0x3fc9d (timer prologue)
ORIG_REDIRECT = bytes.fromhex("ef10c019")  # jal ra, getter
ORIG_NOP = bytes.fromhex("eff0dfdd")    # jal ra, retired-timer

# The watchdog trampoline (assembled for this build; absolute global refs baked
# in: ha=0x3fc97b3c, printer=0x3fc97884, last_ok=0x3fc9caa8, enable=0x3fc9cae0,
# esp_timer via PC-relative call, 5 min = 300000000 us). Source is in the notes.
TRAMPOLINE = bytes.fromhex(
    "411106c6975037fee78060b7b782c93f03c3c2b30d4e6303c30303c34288630fc301"
    "b7d2c93f83a382aab30e754037afe111130f0f306368df0111a8b7d2c93f23a4a2aa"
    "29a0b7d2c93f238002aeb7d2c93f03c502aeb24041018280"
)

NOP_INSTR = bytes.fromhex("13000000")   # addi x0,x0,0


def _find_unique(data: bytes, sig: bytes, what: str) -> int:
    first = data.find(sig)
    if first < 0:
        raise SystemExit(
            f"REFUSE: {what} signature not found — this is not the validated "
            f"firmware build. See the version-support note in this file."
        )
    if data.find(sig, first + 1) >= 0:
        raise SystemExit(f"REFUSE: {what} signature is ambiguous (multiple matches).")
    return first


def _encode_jal(rd: int, offset: int) -> bytes:
    """Encode `jal rd, offset` (offset is target-pc, must be even, +/-1 MiB)."""
    if offset % 2 or not (-(1 << 20) <= offset < (1 << 20)):
        raise SystemExit(f"REFUSE: jal offset {offset:#x} out of range/misaligned.")
    u = offset & 0x1FFFFF
    instr = (
        (((u >> 20) & 1) << 31)
        | (((u >> 1) & 0x3FF) << 21)
        | (((u >> 11) & 1) << 20)
        | (((u >> 12) & 0xFF) << 12)
        | ((rd & 0x1F) << 7)
        | 0x6F
    )
    return instr.to_bytes(4, "little")


def _is_jal_ra(word: int) -> bool:
    return (word & 0x7F) == 0x6F and ((word >> 7) & 0x1F) == 1  # jal, rd=ra(x1)


def _jal_offset(word: int) -> int:
    u = ((((word >> 31) & 1) << 20) | (((word >> 12) & 0xFF) << 12)
         | (((word >> 20) & 1) << 11) | (((word >> 21) & 0x3FF) << 1))
    return u - (1 << 21) if u & (1 << 20) else u


def apply_patch(src: Path, dst: Path) -> None:
    img = LoadFirmwareImage("esp32c3", str(src))
    for seg in img.segments:
        seg.data = bytearray(seg.data)
        if not hasattr(seg, "name"):
            seg.name = ""  # save() reads it unconditionally; only set for ELF loads

    # ── PRIMARY GATE (fail-closed): the parsed-image fingerprint must be on the
    #    allowlist. This decides accept/reject; signatures below are secondary.
    fp = image_fingerprint(img)
    if fp not in ACCEPTED_FINGERPRINTS:
        accepted = "".join(
            f"    {h}  {desc}\n" for h, desc in ACCEPTED_FINGERPRINTS.items())
        raise SystemExit(
            "REFUSE: image fingerprint is not on the accepted allowlist. This tool\n"
            "applies an absolute-address code patch and will not touch an\n"
            "unrecognized build (fail-closed). No output written.\n\n"
            f"  detected fingerprint (parsed app image):\n    {fp}\n\n"
            f"  accepted builds:\n{accepted}\n"
            "  This build must be manually analysed and its addresses/signatures\n"
            "  re-derived (see the reverse-engineering notes at the end of this\n"
            "  file) and hardware-validated before it can be added to the allowlist."
        )
    print(f"fingerprint OK: {fp}\n  = {ACCEPTED_FINGERPRINTS[fp]}")

    irom = next((s for s in img.segments if s.addr == IROM_LOAD), None)
    if irom is None:
        raise SystemExit(f"REFUSE: no IROM segment at {IROM_LOAD:#x}.")
    d = irom.data

    def vaddr(off: int) -> int:
        return IROM_LOAD + off

    # 1. The 0xea5f (59999 ms) threshold is unique — it anchors the retired timer.
    anchor_off = _find_unique(d, ANCHOR_EA5F, "retired-timer 0xea5f threshold")
    anchor_vaddr = vaddr(anchor_off)

    # 2. The retired-timer call site (to NOP) is the unique `jal ra,T` whose target
    #    T starts the timer function (carries HOST_SIG, just before the anchor).
    #    That T is also the trampoline host.
    host_off = nop_off = None
    for o in range(0, len(d) - 3, 2):  # RVC: 2-byte instruction alignment
        w = int.from_bytes(d[o:o + 4], "little")
        if not _is_jal_ra(w):
            continue
        t = vaddr(o) + _jal_offset(w)
        to = t - IROM_LOAD
        if (0 <= to <= len(d) - len(HOST_SIG)
                and anchor_vaddr - 0x140 <= t <= anchor_vaddr
                and bytes(d[to:to + len(HOST_SIG)]) == HOST_SIG):
            if host_off is not None:
                raise SystemExit("REFUSE: multiple retired-timer call sites.")
            host_off, nop_off = to, o
    if host_off is None:
        raise SystemExit("REFUSE: retired-timer call site not found (unrecognized build).")

    # 3. The getter call site (to redirect) is the loop's
    #    `c.mv x8,x10 ; jal ra,getter ; c.mv x9,x10`; its jal target is the getter.
    redirect_off = getter_off = None
    i = 0
    while True:
        i = d.find(b"\x2a\x84", i)  # c.mv x8,x10
        if i < 0:
            break
        if d[i + 6:i + 8] == b"\xaa\x84":  # c.mv x9,x10 after a 4-byte jal
            w = int.from_bytes(d[i + 2:i + 6], "little")
            if _is_jal_ra(w):
                g = vaddr(i + 2) + _jal_offset(w)
                go = g - IROM_LOAD
                if (0 <= go <= len(d) - len(GETTER_SIG)
                        and bytes(d[go:go + len(GETTER_SIG)]) == GETTER_SIG):
                    if redirect_off is not None:
                        raise SystemExit("REFUSE: multiple getter call sites.")
                    redirect_off, getter_off = i + 2, go
        i += 2
    if redirect_off is None:
        raise SystemExit("REFUSE: getter call site not found (unrecognized build).")

    # 3. Exact build-fingerprint gate: every site must sit where the validated
    #    build has it AND hold the exact original bytes. Any deviation => refuse.
    checks = [
        ("host", host_off, HOST_VADDR, ORIG_HOST),
        ("redirect", redirect_off, REDIRECT_VADDR, ORIG_REDIRECT),
        ("nop", nop_off, NOP_VADDR, ORIG_NOP),
        ("getter", getter_off, GETTER_VADDR, GETTER_SIG[:4]),
    ]
    for name, off, want_vaddr, orig in checks:
        if vaddr(off) != want_vaddr:
            raise SystemExit(
                f"REFUSE: {name} at {vaddr(off):#x}, validated build has it at "
                f"{want_vaddr:#x} — unrecognized build, not patching."
            )
        if bytes(d[off:off + len(orig)]) != orig:
            raise SystemExit(f"REFUSE: {name} bytes differ from validated build.")

    if host_off + len(TRAMPOLINE) > nop_off:
        raise SystemExit("REFUSE: trampoline would overrun into live code.")

    # 4. Apply: trampoline body, redirect the getter call to it, retire the old call.
    d[host_off:host_off + len(TRAMPOLINE)] = TRAMPOLINE
    d[redirect_off:redirect_off + 4] = _encode_jal(1, HOST_VADDR - REDIRECT_VADDR)
    d[nop_off:nop_off + 4] = NOP_INSTR
    print(f"patch: trampoline  @ 0x{vaddr(host_off):08x} ({len(TRAMPOLINE)} bytes)")
    print(f"patch: redirect    @ 0x{vaddr(redirect_off):08x} -> 0x{HOST_VADDR:08x}")
    print(f"patch: retire timer@ 0x{vaddr(nop_off):08x} (nop)")

    # 5. Self-check, then save (esptool recomputes checksum + SHA-256).
    assert bytes(d[host_off:host_off + len(TRAMPOLINE)]) == TRAMPOLINE
    img.save(str(dst))
    print(f"wrote {dst}")
    print("Flash to the app slot only; do NOT overwrite the bootloader.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("src", type=Path, help="stock or 70c-patched app .bin")
    parser.add_argument("dst", type=Path, help="output patched .bin")
    args = parser.parse_args()
    apply_patch(args.src, args.dst)


if __name__ == "__main__":
    main()


# ── Reverse-engineering notes (to re-derive the fingerprint for a new build) ──
#
# Trampoline source (RISC-V rv32imc), assembled at the host vaddr:
#     addi  sp, sp, -16
#     sw    ra, 12(sp)
#     call  esp_timer_get_time      # a0 = microseconds (low 32; 5 min < 2^32)
#     lui   t0, %hi(0x3fc98000)
#     lbu   t1, ha_state - 0x3fc98000 (t0)      # broker link state
#     li    t3, 3                                # 3 = CONNECTED
#     beq   t1, t3, .connected
#     lbu   t1, printer_state - 0x3fc98000 (t0)  # printer link state
#     beq   t1, t3, .connected
#     lui   t0, %hi(0x3fc9d000)
#     lw    t2, last_ok - 0x3fc9d000 (t0)
#     sub   t4, a0, t2                           # elapsed_us = now - last_ok
#     li    t5, 300000000                        # 5 minutes
#     bltu  t5, t4, .trip
#     j     .done
# .connected:
#     sw    a0, last_ok(t0')                     # refresh last_ok = now
#     j     .done
# .trip:
#     sb    zero, enable(t0')                    # heat-enable = 0 -> loop turns relay off
# .done:
#     lbu   a0, enable(t0')                      # return enable byte (getter drop-in)
#     lw    ra, 12(sp); addi sp, sp, 16; ret
#
# Fingerprint addresses for the validated build:
#   enable(work_on) byte : 0x3fc9cae0   (from the enable-getter's lbu)
#   ha/broker state      : 0x3fc97b3c   (word; set to 3 by the esp-mqtt handler)
#   printer/WS state     : 0x3fc97884   (word; set to 3 by the printer handler)
#   last_ok scratch      : 0x3fc9caa8   (reused from the retired timer's timestamp)
#   esp_timer_get_time   : 0x40381e36
# For a new build these must be re-found (e.g. via r2ghidra: the enable-getter is
# a 3-instruction leaf `lui;lbu a0,off;ret`; the connection states are read by the
# WebSocket settings serializer and written by the esp-mqtt event handlers; the
# retired timer is the function containing the 0xea5f (59999 ms) threshold). The
# trampoline's absolute immediates must be re-encoded for the new addresses.
#
# Checklist to add a new accepted build:
#   1. Re-derive, for that build: HOST_VADDR, REDIRECT_VADDR, NOP_VADDR,
#      GETTER_VADDR, the ORIG_* bytes, the HOST_SIG/GETTER_SIG/ANCHOR_EA5F
#      signatures, and the five fingerprint addresses above.
#   2. Re-assemble the trampoline for that build's addresses (see source above);
#      update TRAMPOLINE (and the site vaddrs / signatures) — these are currently
#      single-build constants, so a second build needs them keyed per fingerprint.
#   3. Compute the image fingerprint:
#        python3 -c "import patch_panda_breath_watchdog as p, esptool.bin_image as b; \
#                    print(p.image_fingerprint(b.LoadFirmwareImage('esp32c3','app.bin')))"
#      and add it to ACCEPTED_FINGERPRINTS with a description.
#   4. Validate on hardware before trusting.
