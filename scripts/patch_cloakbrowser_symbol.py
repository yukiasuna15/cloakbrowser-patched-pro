#!/usr/bin/env python3
"""Neutralize CloakBrowser Pro license/session enforcement in the binary.

The Pro Chromium binary enforces the "N concurrent sessions" seat limit in
`ungoogled::LicenseRuntime`, a small C++ runtime that:

  1. `Start()`  - called once at browser boot (PreMainMessageLoopRun): POSTs
                  /api/license/session/start with {license_key, install_id,
                  instance_id, platform, version}, verifies the Ed25519-signed
                  lease token in the response, then exits the process with
                  code 76 (seat limit) / 77 (bad key) / 78 (server unreachable)
                  / 79 (config problem) on any denial.
  2. `End()`    - called at shutdown: POSTs /api/license/session/end.
  3. `SendHeartbeat()` - periodic heartbeat scheduled from the start response.

This script rewrites the first bytes of `Start()` and `End()` to
`xor eax,eax; ret` so neither ever runs: no request is sent, no response is
verified, no exit code is ever raised, and no seat is ever registered
server-side. All other Pro features (the fingerprinting patches) are
untouched.

The binary ships with a full symtab, so target addresses are resolved by
symbol name -- this works across versions as long as the symbols survive.

Usage:
    python3 patch_cloakbrowser.py [path-to-chrome]
    # default: ~/.cloakbrowser/chromium-<ver>-pro/chrome

    python3 patch_cloakbrowser.py --restore
"""
from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys
from pathlib import Path

SYMBOLS = [
    "_ZN9ungoogled14LicenseRuntime5StartE13scoped_refptrIN7network22SharedURLLoaderFactoryEES4_",
    "_ZN9ungoogled14LicenseRuntime3EndEv",
]
PROLOGUE = bytes.fromhex("554889e5")  # push rbp; mov rbp,rsp
PATCH = bytes.fromhex("31c0c3")       # xor eax,eax; ret


def find_default_binary() -> Path:
    cache = Path.home() / ".cloakbrowser"
    candidates = sorted(cache.glob("chromium-*-pro/chrome"), reverse=True)
    if not candidates:
        sys.exit("no Pro binary found under ~/.cloakbrowser")
    return candidates[0]


def read_symbols(binary: Path) -> dict[str, int]:
    """Parse `nm` output for the target symbols -> {name: vaddr}."""
    out = subprocess.run(
        ["nm", str(binary)], capture_output=True, text=True, check=True
    ).stdout
    wanted = set(SYMBOLS)
    found: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in wanted:
            found[parts[2]] = int(parts[0], 16)
    missing = wanted - found.keys()
    if missing:
        sys.exit(f"symbols not found (binary layout changed?): {missing}")
    return found


def build_vaddr_map(binary: Path) -> list[tuple[int, int, int]]:
    """PT_LOAD segments as (vaddr, file_offset, filesz)."""
    data = binary.read_bytes()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, off)[0] == 1:  # PT_LOAD
            p_offset = struct.unpack_from("<Q", data, off + 0x08)[0]
            p_vaddr = struct.unpack_from("<Q", data, off + 0x10)[0]
            p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
            loads.append((p_vaddr, p_offset, p_filesz))
    return loads


def vaddr_to_off(loads: list[tuple[int, int, int]], vaddr: int) -> int:
    for va, off, size in loads:
        if va <= vaddr < va + size:
            return off + (vaddr - va)
    raise ValueError(f"vaddr {vaddr:#x} not inside any PT_LOAD segment")


def patch(binary: Path) -> None:
    backup = binary.with_name(binary.name + ".orig-backup")
    if not backup.exists():
        shutil.copy2(binary, backup)
        print(f"backup written: {backup}")
    else:
        print(f"backup already exists: {backup}")

    syms = read_symbols(binary)
    loads = build_vaddr_map(binary)
    buf = bytearray(binary.read_bytes())

    for name, vaddr in syms.items():
        off = vaddr_to_off(loads, vaddr)
        current = bytes(buf[off:off + len(PROLOGUE)])
        if current == PATCH:
            print(f"already patched: {name} @ {vaddr:#x}")
            continue
        if current != PROLOGUE:
            sys.exit(f"{name}: unexpected prologue {current.hex()} "
                     f"(expected {PROLOGUE.hex()}) -- refusing to patch")
        buf[off:off + len(PATCH)] = PATCH
        print(f"patched {name} @ {vaddr:#x} (file off {off:#x}): "
              f"{current.hex()} -> {PATCH.hex()}")

    binary.write_bytes(bytes(buf))
    print("done")


def restore(binary: Path) -> None:
    backup = binary.with_name(binary.name + ".orig-backup")
    if not backup.exists():
        sys.exit(f"no backup at {backup}")
    shutil.copy2(backup, binary)
    print(f"restored {binary} from {backup}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary", nargs="?", type=Path, help="path to chrome binary")
    ap.add_argument("--restore", action="store_true",
                    help="restore the original binary from backup")
    args = ap.parse_args()

    target = args.binary or find_default_binary()
    if not target.exists():
        sys.exit(f"binary not found: {target}")
    print(f"target: {target}")

    if args.restore:
        restore(target)
    else:
        patch(target)
