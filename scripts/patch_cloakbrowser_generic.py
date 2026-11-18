#!/usr/bin/env python3
"""Neutralize CloakBrowser Pro license/session enforcement in the Chromium binary.

Works on binaries that have been STRIPPED (no symtab) -- version 156.0.8078.47.1
and later. For unstripped builds use the symbol-driven variant.

HOW IT FINDS THE FUNCTIONS WITHOUT SYMBOLS
------------------------------------------
The license runtime keeps its API/JSON strings alive in .rodata. Those strings
are referenced by `lea reg, [rip+disp32]`. From the string xrefs we walk back to
the enclosing function (cc-padded boundary + `push rbp; mov rbp, rsp` prologue),
then classify:

  * Start  -> the function containing "/api/license/session/start" AND
              "CLOAKBROWSER_LICENSE_KEY" / "install_id" (lazy-init guard
              `cmp byte [rdi+0x122], 0`), frame sub rsp,0xc8
  * End    -> the function containing "/api/license/session/end"

WHAT THE PATCH DOES
-------------------
Rewrite the first bytes of those two functions to `xor eax,eax; ret` (+nop).
No session/start request, no heartbeat, no lease verification, no exit
76/77/78/79. Every Pro fingerprint patch stays intact.

The binary is NOT re-verified at launch: the Ed25519 signature is only checked
when the archive is downloaded, so a patched binary on disk runs fine.

Usage:
    python3 patch_cloakbrowser_generic.py              # newest *-pro binary
    python3 patch_cloakbrowser_generic.py <path/chrome>
    python3 patch_cloakbrowser_generic.py --restore
    python3 patch_cloakbrowser_generic.py --dry-run
"""
from __future__ import annotations

import argparse
import re
import shutil
import struct
import sys
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    sys.exit("pyelftools required:  pip install pyelftools")

PROLOGUE = bytes.fromhex("554889e5")   # push rbp; mov rbp,rsp
PATCH = bytes.fromhex("31c0c390")      # xor eax,eax; ret; nop

STR_START = b"/api/license/session/start"
STR_END = b"/api/license/session/end"
STR_KEY = b"CLOAKBROWSER_LICENSE_KEY"
STR_INSTALL = b"install_id"


def find_default_binary() -> Path:
    root = Path.home() / ".cloakbrowser"
    cands = sorted(root.glob("chromium-*-pro/chrome"))
    if not cands:
        sys.exit("no Pro binary found under ~/.cloakbrowser")
    return cands[-1]


class Image:
    def __init__(self, path: Path):
        self.path = path
        self.data = bytearray(path.read_bytes())
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            self.loads = [
                (s["p_vaddr"], s["p_offset"], s["p_filesz"])
                for s in elf.iter_segments()
                if s["p_type"] == "PT_LOAD"
            ]

    def va2off(self, va: int) -> int:
        for va0, off0, size in self.loads:
            if va0 <= va < va0 + size:
                return off0 + (va - va0)
        raise ValueError(f"vaddr {va:#x} not mapped")

    def off2va(self, off: int):
        for va0, off0, size in self.loads:
            if off0 <= off < off0 + size:
                return va0 + (off - off0)
        return None

    def string_vaddr(self, needle: bytes):
        i = self.data.find(needle)
        return None if i < 0 else self.off2va(i)

    def lea_xrefs(self, target_va: int):
        """All vaddrs of `lea r64,[rip+disp32]` pointing at target_va."""
        out = []
        pat = re.compile(rb"\x48\x8d([\x05\x0d\x15\x1d\x25\x2d\x35\x3d])(....)", re.S)
        for m in pat.finditer(self.data):
            disp = struct.unpack("<i", m.group(2))[0]
            va = self.off2va(m.start())
            if va is None:
                continue
            if va + 7 + disp == target_va:
                out.append(va)
        return out

    def enclosing_func(self, xref_va: int, max_back: int = 0x8000):
        """Walk back to the cc-padded boundary that starts this function."""
        off = self.va2off(xref_va)
        j = off
        while j > off - max_back and j > 0:
            if self.data[j] == 0xCC and self.data[j + 1] != 0xCC:
                k = j
                while self.data[k] == 0xCC:
                    k -= 1
                start = k + 1
                if bytes(self.data[start:start + 4]) == PROLOGUE:
                    return self.off2va(start)
            j -= 1
        return None

    def func_contains(self, needle: bytes):
        """Enclosing function vaddr of every xref to needle (deduped)."""
        va = self.string_vaddr(needle)
        if va is None:
            return []
        seen = []
        for x in self.lea_xrefs(va):
            f = self.enclosing_func(x)
            if f and f not in seen:
                seen.append(f)
        return seen


def locate(img: Image):
    starts = img.func_contains(STR_START)
    ends = img.func_contains(STR_END)
    key_fns = img.func_contains(STR_KEY)
    inst_fns = img.func_contains(STR_INSTALL)

    # Start = a session/start function that also touches the license key or
    # install_id (the request builder).
    start = None
    for f in starts:
        if f in key_fns or f in inst_fns:
            start = f
            break
    if start is None and starts:
        start = starts[0]

    end = ends[0] if ends else None
    return start, end, starts, ends


def patch(img: Image, start, end, dry_run: bool):
    backup = img.path.with_name(img.path.name + ".orig-backup")
    if not dry_run:
        if not backup.exists():
            shutil.copy2(img.path, backup)
            print(f"backup: {backup}")
        else:
            print(f"backup exists: {backup}")

    targets = [(start, "LicenseRuntime::Start")]
    if end and end != start:
        targets.append((end, "LicenseRuntime::End"))

    for va, name in targets:
        off = img.va2off(va)
        cur = bytes(img.data[off:off + 4])
        if cur[:3] == PATCH[:3]:
            print(f"already patched: {name} @ {va:#x}")
            continue
        if bytes(cur[:2]) == PROLOGUE[:2] and cur[2] != PROLOGUE[2]:
            pass
        if cur[:3] != PROLOGUE:
            sys.exit(f"{name} @ {va:#x}: prologue {cur.hex()} != {PROLOGUE.hex()} -- refusing")
        print(f"{'would patch' if dry_run else 'patched'} {name} @ {va:#x} "
              f"(file {off:#x}): {cur.hex()} -> {PATCH.hex()}")
        if not dry_run:
            img.data[off:off + len(PATCH)] = PATCH

    if not dry_run:
        img.path.write_bytes(bytes(img.data))
        print("written")


def restore(path: Path):
    backup = path.with_name(path.name + ".orig-backup")
    if not backup.exists():
        sys.exit(f"no backup at {backup}")
    shutil.copy2(backup, path)
    print(f"restored {path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", nargs="?", type=Path)
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    target = args.binary or find_default_binary()
    if not target.exists():
        sys.exit(f"binary not found: {target}")
    print(f"target: {target}")

    if args.restore:
        restore(target)
        sys.exit(0)

    img = Image(target)
    start, end, starts, ends = locate(img)
    print(f"session/start funcs: {[hex(x) for x in starts]}")
    print(f"session/end   funcs: {[hex(x) for x in ends]}")
    if not start:
        sys.exit("could not locate Start -- binary layout changed")
    print(f"START = {start:#x}   END = {end:#x}" if end else f"START = {start:#x}   END = ?")
    patch(img, start, end, args.dry_run)
