#!/usr/bin/env python3
"""
CloakBrowser binary integrity guardian.

Watches the pinned Pro Chromium binary. If it is replaced (cloakbrowser update,
npm reinstall, fresh download) the license patch is gone and the browser will
start exiting 76/77/78/79 -- so this re-applies the patch automatically.

Detection strategy
------------------
The pinned binary is identified by its SHA-256. On every check:

  * binary missing?            -> nothing to do (wait for install)
  * hash == patched baseline AND sites patched -> healthy, sleep
  * sites already patched      -> record new baseline, healthy
  * sites unpatched after an update -> locate + patch, then re-baseline
  * sites unpatched and hash differs from baseline -> the build was replaced
        -> locate the LicenseRuntime sites for the NEW build and patch

Site location is signature-driven (no hardcoded vaddrs required):

  1. find the rodata strings  "/api/license/session/start" and "/api/license/session/end"
  2. find `lea r64,[rip+disp32]` xrefs to them
  3. walk back to the enclosing function (cc padding + `push rbp; mov rbp, rsp`)
  4. classify Start (also references CLOAKBROWSER_LICENSE_KEY / install_id)

If locating fails the guardian does NOT touch the binary -- it logs and retries,
so a layout change can never corrupt a working install.

Usage:
    cloak_guard.py --once          # single check (used by systemd timer)
    cloak_guard.py --daemon        # watch forever
    cloak_guard.py --daemon --interval 30
    cloak_guard.py --status
    cloak_guard.py --restore-baseline
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    sys.exit("pyelftools required: pip install pyelftools")

HOME = Path.home()
CACHE = HOME / ".cloakbrowser"
STATE_DIR = HOME / ".cloakbrowser-guard"
STATE_FILE = STATE_DIR / "state.json"
LOG_FILE = STATE_DIR / "guard.log"
BASELINE_FILE = STATE_DIR / "baseline.json"

PROLOGUE = bytes.fromhex("554889e5")   # push rbp; mov rbp,rsp
PATCH = bytes.fromhex("31c0c390")      # xor eax,eax; ret; nop

STR_START = b"/api/license/session/start"
STR_END = b"/api/license/session/end"
STR_KEY = b"CLOAKBROWSER_LICENSE_KEY"
STR_INSTALL = b"install_id"

CHECK_INTERVAL = 60


# ------------------------------------------------------------------ logging
def log(msg: str, level: str = "INFO") -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts} [{level}] {msg}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


# ------------------------------------------------------------------ state
def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ ELF image
class Image:
    def __init__(self, path: Path):
        self.path = path
        self.data = bytearray(path.read_bytes())
        with path.open("rb") as fh:
            elf = ELFFile(fh)
            self.loads = [
                (s["p_vaddr"], s["p_offset"], s["p_filesz"])
                for s in elf.iter_segments()
                if s["p_type"] == "PT_LOAD"
            ]

    def va2off(self, va: int):
        for va0, off0, size in self.loads:
            if va0 <= va < va0 + size:
                return off0 + (va - va0)
        return None

    def off2va(self, off: int):
        for va0, off0, size in self.loads:
            if off0 <= off < off0 + size:
                return va0 + (off - off0)
        return None

    def string_va(self, needle: bytes):
        i = bytes(self.data).find(needle)
        return None if i < 0 else self.off2va(i)

    def lea_xrefs(self, target_va: int):
        import re
        import struct
        out = []
        pat = re.compile(rb"\x48\x8d([\x05\x0d\x15\x1d\x25\x2d\x35\x3d])(....)", re.S)
        for m in pat.finditer(bytes(self.data)):
            disp = struct.unpack("<i", m.group(2))[0]
            va = self.off2va(m.start())
            if va is None:
                continue
            if va + 7 + disp == target_va:
                out.append(va)
        return out

    def enclosing_func(self, xref_va: int, max_back: int = 0x8000):
        off = self.va2off(xref_va)
        if off is None:
            return None
        j = off
        while j > off - max_back and j > 0:
            if self.data[j] == 0xCC and self.data[j + 1] != 0xCC:
                k = j
                while k > 0 and self.data[k] == 0xCC:
                    k -= 1
                start = k + 1
                if bytes(self.data[start:start + 4]) == PROLOGUE:
                    return self.off2va(start)
            j -= 1
        return None

    def funcs_for(self, needle: bytes):
        va = self.string_va(needle)
        if va is None:
            return []
        seen = []
        for x in self.lea_xrefs(va):
            f = self.enclosing_func(x)
            if f and f not in seen:
                seen.append(f)
        return seen


def locate_sites(img: Image):
    """Return (start_va, end_va) or (None, None)."""
    starts = img.funcs_for(STR_START)
    ends = img.funcs_for(STR_END)
    key_fns = set(img.funcs_for(STR_KEY))
    inst_fns = set(img.funcs_for(STR_INSTALL))

    start = None
    for f in starts:
        if f in key_fns or f in inst_fns:
            start = f
            break
    if start is None and starts:
        start = starts[0]
    end = ends[0] if ends else None
    return start, end


def is_patched(img: Image, va: int) -> bool | None:
    """True=patched, False=pristine prologue, None=unexpected bytes."""
    off = img.va2off(va)
    if off is None:
        return None
    cur = bytes(img.data[off:off + 4])
    if cur[:3] == PATCH[:3]:
        return True
    if cur[:4] == PROLOGUE:
        return False
    return None


# ------------------------------------------------------------------ patching
def patch_binary(path: Path, force_locate: bool = False) -> dict:
    """Locate + patch both sites. Returns a result dict."""
    state = load_state()
    img = Image(path)

    sites = state.get("sites") or {}
    if force_locate or not sites.get("start"):
        start, end = locate_sites(img)
        if not start:
            return {"ok": False, "reason": "could not locate LicenseRuntime::Start"}
        sites = {"start": start, "end": end}
        log(f"located sites for this build: start={start:#x} end={end if end is None else hex(end)}")
    else:
        start, end = sites["start"], sites.get("end")

    changed = []
    for va, name in ((start, "Start"), (end, "End")):
        if va is None:
            continue
        st = is_patched(img, va)
        if st is True:
            log(f"{name} @ {va:#x}: already patched")
            continue
        if st is False:
            off = img.va2off(va)
            img.data[off:off + len(PATCH)] = PATCH
            changed.append(f"{name}@{va:#x}")
            log(f"{name} @ {va:#x}: PATCHED")
        else:
            # unexpected bytes -> try a full re-locate once
            log(f"{name} @ {va:#x}: unexpected prologue, re-locating", "WARN")
            s2, e2 = locate_sites(img)
            if s2:
                sites = {"start": s2, "end": e2}
                state["sites"] = sites
                img = Image(path)
                st2 = is_patched(img, s2)
                if st2 is False:
                    off = img.va2off(s2)
                    img.data[off:off + len(PATCH)] = PATCH
                    changed.append(f"Start@{s2:#x}")
                    log(f"Start @ {s2:#x}: PATCHED after relocate")
                start, end = s2, e2
            break

    if changed:
        backup = path.with_name(path.name + ".guard-backup")
        if not backup.exists():
            shutil.copy2(path, backup)
            log(f"backup written: {backup.name}")
        path.write_bytes(bytes(img.data))
        log(f"binary rewritten ({', '.join(changed)})")

    state["sites"] = sites
    state["patched_at"] = datetime.now(timezone.utc).isoformat()
    state["baseline_sha256"] = sha256_of(path)
    save_state(state)
    return {"ok": True, "changed": changed, "sites": sites}


# ------------------------------------------------------------------ check
def current_binary() -> Path | None:
    dirs = sorted(CACHE.glob("chromium-*-pro/chrome"))
    return dirs[-1] if dirs else None


def check_once() -> dict:
    binp = current_binary()
    if not binp:
        log("no Pro binary installed yet -- waiting", "WARN")
        return {"status": "no-binary"}

    state = load_state()
    digest = sha256_of(binp)
    prev = state.get("baseline_sha256")
    version = binp.parent.name.replace("chromium-", "").replace("-pro", "")
    known = state.get("version")

    replaced = prev is not None and prev != digest
    new_build = known != version

    if replaced or new_build:
        log(f"CHANGE DETECTED version={version} replaced={replaced} new_build={new_build}", "WARN")

    res = patch_binary(binp, force_locate=bool(replaced or new_build))
    state = load_state()
    state["version"] = version
    save_state(state)

    if not res.get("ok"):
        log(f"patch failed: {res.get('reason')}", "ERROR")
        return {"status": "failed", "reason": res.get("reason")}

    patched = res.get("changed")
    if patched:
        log(f"re-patched after tamper: {patched}", "WARN")
        return {"status": "repatched", "changed": patched, "version": version}

    return {"status": "healthy", "version": version}


# ------------------------------------------------------------------ daemon
class Guard:
    def __init__(self, interval: int):
        self.interval = interval
        self.running = True

    def stop(self, *_):
        self.running = False
        log("shutdown requested")

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        log(f"guard started (interval={self.interval}s, pid={os.getpid()})")
        while self.running:
            try:
                r = check_once()
                log(f"check -> {r.get('status')}")
            except Exception as exc:  # never die on a transient error
                log(f"check raised {type(exc).__name__}: {exc}", "ERROR")
            for _ in range(self.interval):
                if not self.running:
                    break
                time.sleep(1)
        log("guard stopped")


# ------------------------------------------------------------------ status
def status() -> None:
    binp = current_binary()
    state = load_state()
    print("=== cloak_guard status ===")
    print(f"  state dir : {STATE_DIR}")
    print(f"  binary    : {binp}")
    if binp:
        print(f"  version   : {binp.parent.name}")
        print(f"  sha256    : {sha256_of(binp)[:32]}...")
        img = Image(binp)
        sites = state.get("sites") or {}
        if sites.get("start"):
            print(f"  Start @   : {sites['start']:#x}  patched={is_patched(img, sites['start'])}")
        if sites.get("end"):
            print(f"  End   @   : {sites['end']:#x}  patched={is_patched(img, sites['end'])}")
    print(f"  baseline  : {str(state.get('baseline_sha256'))[:32]}...")
    print(f"  patched_at: {state.get('patched_at')}")
    print(f"  log file  : {LOG_FILE}")


def restore_baseline() -> None:
    binp = current_binary()
    if not binp:
        sys.exit("no binary")
    state = load_state()
    state["baseline_sha256"] = sha256_of(binp)
    state["patched_at"] = datetime.now(timezone.utc).isoformat()
    save_state(state)
    log("baseline restored to current binary hash")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--once", action="store_true", help="single check then exit")
    g.add_argument("--daemon", action="store_true", help="watch continuously")
    g.add_argument("--status", action="store_true")
    g.add_argument("--restore-baseline", action="store_true")
    ap.add_argument("--interval", type=int, default=CHECK_INTERVAL)
    args = ap.parse_args()

    if args.status:
        status()
    elif args.restore_baseline:
        restore_baseline()
    elif args.once:
        log(f"single check -> {check_once()}")
    elif args.daemon:
        Guard(args.interval).run()


if __name__ == "__main__":
    main()
