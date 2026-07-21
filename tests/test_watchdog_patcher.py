#!/usr/bin/env python3
"""Tests for patch_panda_breath_watchdog.py — the fail-closed version gate.

The firmware is proprietary and not shipped here, so the fingerprint/gate LOGIC
is tested synthetically (always runs, no firmware needed). Full end-to-end tests
against real images run only when you point these env vars at your own OEM app
images:

    PANDA_WATCHDOG_STOCK_IMAGE=/path/to/v1.0.4_stock.bin   # an accepted build
    PANDA_WATCHDOG_70C_IMAGE=/path/to/v1.0.4_70c.bin       # accepted 70C variant
    PANDA_WATCHDOG_OTHER_IMAGE=/path/to/some_other.bin     # an UNapproved build

Run:  python3 tests/test_watchdog_patcher.py   (also discoverable by pytest)
"""
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "tools" / "patch_panda_breath_watchdog.py"
_spec = importlib.util.spec_from_file_location("wd", _TOOL)
wd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wd)


# ── synthetic fixtures (no esptool image needed) ──────────────────────────────
class _Seg:
    def __init__(self, addr, data):
        self.addr = addr
        self.data = bytearray(data)


class _Img:
    def __init__(self, entry, segs):
        self.entrypoint = entry
        self.segments = segs


def _fake(entry=0x40380438):
    return _Img(entry, [_Seg(0x3C0E0020, b"ro" * 32),
                        _Seg(0x42000020, b"\x13\x00\x00\x00" * 16)])


# ── gate-logic tests (always run) ─────────────────────────────────────────────
def test_fingerprint_deterministic():
    a, b = wd.image_fingerprint(_fake()), wd.image_fingerprint(_fake())
    assert a == b and len(a) == 64


def test_fingerprint_sensitive_to_one_byte():
    img = _fake()
    base = wd.image_fingerprint(img)
    img.segments[1].data[0] ^= 0x01
    assert wd.image_fingerprint(img) != base


def test_fingerprint_sensitive_to_entry_and_layout():
    assert wd.image_fingerprint(_fake(0x40380438)) != wd.image_fingerprint(_fake(0x40380500))
    img = _fake()
    img.segments[1].data.append(0x00)  # length change
    assert wd.image_fingerprint(img) != wd.image_fingerprint(_fake())


def test_allowlist_is_fail_closed_and_well_formed():
    # an unknown image's fingerprint must NOT be accepted
    assert wd.image_fingerprint(_fake()) not in wd.ACCEPTED_FINGERPRINTS
    # accepted entries are valid 64-char lowercase SHA-256 hex
    assert wd.ACCEPTED_FINGERPRINTS, "allowlist must not be empty"
    for h in wd.ACCEPTED_FINGERPRINTS:
        assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)


# ── end-to-end tests against real images (env-gated) ──────────────────────────
def _load(path):
    from esptool.bin_image import LoadFirmwareImage
    return LoadFirmwareImage("esp32c3", path)


def _apply(src):
    """Return the output path on success, or the raised SystemExit on refusal."""
    out = Path(tempfile.mkdtemp()) / "patched.bin"
    try:
        wd.apply_patch(Path(src), out)
        return out
    except SystemExit as e:
        return e


def test_accepted_stock_patches():
    p = os.environ.get("PANDA_WATCHDOG_STOCK_IMAGE")
    if not p:
        print("skip test_accepted_stock_patches (PANDA_WATCHDOG_STOCK_IMAGE unset)")
        return
    assert wd.image_fingerprint(_load(p)) in wd.ACCEPTED_FINGERPRINTS
    r = _apply(p)
    assert isinstance(r, Path) and r.stat().st_size > 0, f"stock should patch, got {r}"


def test_accepted_70c_patches():
    p = os.environ.get("PANDA_WATCHDOG_70C_IMAGE")
    if not p:
        print("skip test_accepted_70c_patches (PANDA_WATCHDOG_70C_IMAGE unset)")
        return
    r = _apply(p)
    assert isinstance(r, Path) and r.stat().st_size > 0, f"70c should patch, got {r}"


def test_one_byte_modified_is_refused():
    p = os.environ.get("PANDA_WATCHDOG_STOCK_IMAGE")
    if not p:
        print("skip test_one_byte_modified_is_refused (PANDA_WATCHDOG_STOCK_IMAGE unset)")
        return
    img = _load(p)
    for s in img.segments:
        s.data = bytearray(s.data)
        if not hasattr(s, "name"):
            s.name = ""
    for s in img.segments:            # flip one byte in the code segment
        if s.addr == wd.IROM_LOAD:
            s.data[0x100] ^= 0x01
            break
    mod = Path(tempfile.mkdtemp()) / "modified.bin"
    img.save(str(mod))
    r = _apply(str(mod))
    assert isinstance(r, SystemExit), "a one-byte-modified image must be refused"


def test_unapproved_hash_is_refused():
    p = os.environ.get("PANDA_WATCHDOG_OTHER_IMAGE")
    if not p:
        print("skip test_unapproved_hash_is_refused (PANDA_WATCHDOG_OTHER_IMAGE unset)")
        return
    assert wd.image_fingerprint(_load(p)) not in wd.ACCEPTED_FINGERPRINTS
    r = _apply(p)
    assert isinstance(r, SystemExit), "an unapproved-hash image must be refused"


if __name__ == "__main__":
    failures = 0
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            try:
                _fn()
                print(f"PASS {_name}")
            except AssertionError as _e:
                failures += 1
                print(f"FAIL {_name}: {_e}")
    print(f"\n{'FAILED' if failures else 'OK'} ({failures} failure(s))")
    sys.exit(1 if failures else 0)
