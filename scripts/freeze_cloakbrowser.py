#!/usr/bin/env python3
"""
CloakBrowser hard freeze -- pin to the currently installed version, permanently.

Four independent layers, so that even an explicit `cloakbrowser update` (which
ignores CLOAKBROWSER_AUTO_UPDATE) cannot move the install:

  LAYER 1  env vars in ~/.bashrc + ~/.profile + ~/.zshrc (if present)
             CLOAKBROWSER_AUTO_UPDATE=false
             CLOAKBROWSER_VERSION=<pinned>
             CLOAKBROWSER_LICENSE_API=http://127.0.0.1:1   (blocks update check)
  LAYER 2  version marker files pinned to <pinned> and mtime refreshed every run
  LAYER 3  getProLatestRelease() in license.js patched to return the pinned
           release from cache and NEVER hit the network  (kills `update`)
  LAYER 4  the pinned version directory is made immutable where possible
           (chattr +i) and a re-patch guard runs to reapply the license patch
           after any binary replacement

Idempotent: safe to run repeatedly.

Usage:
    python3 freeze_cloakbrowser.py            # freeze at installed version
    python3 freeze_cloakbrowser.py --version 156.0.8078.47.1
    python3 freeze_cloakbrowser.py --unfreeze
    python3 freeze_cloakbrowser.py --status
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HOME = Path.home()
CACHE = HOME / ".cloakbrowser"
NPM_DIST = HOME / ".npm-global/lib/node_modules/cloakbrowser/dist"
PLATFORM = "linux-x64"

ENV_BLOCK_BEGIN = "# >>> cloakbrowser freeze >>>"
ENV_BLOCK_END = "# <<< cloakbrowser freeze <<<"

RC_FILES = [HOME / ".bashrc", HOME / ".profile", HOME / ".zshrc"]

# license runtime patch for 156.0.8078.47.1 (see patch_cloakbrowser_generic.py)
LICENSE_PATCH = {
    0xDE79AC0: "LicenseRuntime::Start",
    0xDE7BAD0: "LicenseRuntime::End",
}
PATCH_BYTES = bytes.fromhex("31c0c390")   # xor eax,eax; ret; nop


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def detect_installed() -> str | None:
    dirs = sorted(CACHE.glob("chromium-*-pro"))
    if not dirs:
        return None
    name = dirs[-1].name                      # chromium-156.0.8078.47.1-pro
    return name.replace("chromium-", "").replace("-pro", "")


# ---------------------------------------------------------------- layer 1
def write_env_block(pinned: str) -> None:
    block = f"""{ENV_BLOCK_BEGIN}
export CLOAKBROWSER_AUTO_UPDATE=false
export CLOAKBROWSER_VERSION={pinned}
export CLOAKBROWSER_LICENSE_API=http://127.0.0.1:1
{ENV_BLOCK_END}
"""
    for rc in RC_FILES:
        if not rc.exists():
            continue
        txt = rc.read_text(errors="ignore")
        if ENV_BLOCK_BEGIN in txt:
            txt = re.sub(
                re.escape(ENV_BLOCK_BEGIN) + r".*?" + re.escape(ENV_BLOCK_END) + r"\n?",
                block, txt, flags=re.S,
            )
        else:
            txt = txt.rstrip("\n") + "\n\n" + block
        rc.write_text(txt)
        print(f"  env block -> {rc}")


# ---------------------------------------------------------------- layer 2
def pin_markers(pinned: str) -> None:
    marker = CACHE / f"latest_pro_version_{PLATFORM}"
    res = CACHE / f".last_pro_version_resolution_{PLATFORM}"
    chk = CACHE / f".last_pro_version_check_{PLATFORM}"

    for f in (marker, res, chk):
        if f.exists():
            run(["chattr", "-i", str(f)])     # unlock before writing

    marker.write_text(pinned)
    res.write_text(json.dumps({
        "version": pinned,
        "requested_channel": "stable",
        "resolved_channel": "stable",
        "fallback": False,
    }))
    chk.write_text("0")                       # mtime refreshed below
    os.utime(chk, None)
    os.utime(res, None)
    print(f"  markers pinned -> {pinned}")

    for f in (marker, res):
        r = run(["chattr", "+i", str(f)])
        if r.returncode == 0:
            print(f"  immutable -> {f.name}")


# ---------------------------------------------------------------- layer 3
PATCH_LICENSE_JS = '''
// --- cloakbrowser freeze: offline pin (patched) ---
export async function getProLatestRelease(releaseChannel) {
    // FROZEN: never consult the network. Report the pinned local build.
    const { getCacheDir } = await import("./config.js");
    const fs = await import("node:fs");
    const path = await import("node:path");
    const marker = path.join(getCacheDir(), ".last_pro_version_resolution_linux-x64");
    try {
        const cached = JSON.parse(fs.readFileSync(marker, "utf-8"));
        return {
            version: cached.version,
            requestedChannel: cached.requested_channel ?? "stable",
            resolvedChannel: cached.resolved_channel ?? "stable",
            fallback: false,
        };
    } catch {
        return null;
    }
}
'''


def patch_license_js(pinned: str) -> None:
    target = NPM_DIST / "license.js"
    if not target.exists():
        print(f"  license.js not found at {target} -- skipped")
        return

    src = target.read_text()
    orig = NPM_DIST / "license.js.orig-freeze"

    if "cloakbrowser freeze: offline pin" in src:
        print("  license.js already frozen")
        return

    if not orig.exists():
        shutil.copy2(target, orig)
        print(f"  backup -> {orig.name}")

    # splice: replace the whole getProLatestRelease body with our offline version
    start = src.find("export async function getProLatestRelease(")
    if start < 0:
        print("  getProLatestRelease not found -- skipped")
        return

    # find the matching closing brace of the function
    i = src.find("{", start)
    depth = 0
    end = i
    while end < len(src):
        c = src[end]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        end += 1
    end += 1

    new_src = src[:start] + PATCH_LICENSE_JS.strip() + src[end:]
    target.write_text(new_src)
    print(f"  getProLatestRelease -> offline pin (was {end-start} chars)")


def unpatch_license_js() -> None:
    target = NPM_DIST / "license.js"
    orig = NPM_DIST / "license.js.orig-freeze"
    if orig.exists():
        shutil.copy2(orig, target)
        print("  license.js restored from backup")


# ---------------------------------------------------------------- layer 4
def lock_version_dir(pinned: str) -> None:
    d = CACHE / f"chromium-{pinned}-pro"
    if not d.exists():
        print(f"  {d.name} missing -- skipped")
        return
    r = run(["chattr", "+i", str(d)])
    print(f"  chattr +i {d.name}: {'ok' if r.returncode == 0 else 'unavailable (no CAP)'}")


def repair_binary(pinned: str) -> None:
    """Re-apply the license patch if a fresh binary replaced ours."""
    ch = CACHE / f"chromium-{pinned}-pro/chrome"
    if not ch.exists():
        return
    data = bytearray(ch.read_bytes())
    changed = False
    for va, name in LICENSE_PATCH.items():
        # file offset == vaddr for this ELF layout (PT_LOAD p_offset==p_vaddr region)
        off = va - 0x1000
        # locate by scanning the known offset range around it
        found = None
        for probe in range(off - 0x40, off + 0x40):
            if data[probe:probe + 3] == PATCH_BYTES[:3]:
                found = probe
                break
            if data[probe:probe + 4] == bytes.fromhex("554889e5"):
                found = probe
                break
        if found is None:
            print(f"  {name}: site not found @ ~{va:#x}")
            continue
        if data[found:found + 3] == PATCH_BYTES[:3]:
            print(f"  {name}: already patched")
            continue
        if data[found:found + 4] != bytes.fromhex("554889e5"):
            print(f"  {name}: unexpected bytes {data[found:found+4].hex()} -- skipped")
            continue
        data[found:found + 4] = PATCH_BYTES
        changed = True
        print(f"  {name}: re-patched @ {found:#x}")

    if changed:
        ch.write_bytes(bytes(data))
        print("  binary rewritten")


def verify(pinned: str) -> None:
    print("\n=== VERIFY ===")
    ch = CACHE / f"chromium-{pinned}-pro/chrome"
    print(f"  installed dir : {ch.parent.name}")
    print(f"  binary exists : {ch.exists()}")

    r = run(["node", "-e", """
import { binaryInfo } from '%s/index.js';
const i = binaryInfo();
console.log('  binaryInfo.version  :', i.version);
console.log('  binaryInfo.installed:', i.installed);
""" % NPM_DIST])
    print(r.stdout.rstrip() or r.stderr.rstrip())

    r = run(["node", "-e", """
import { checkForProUpdate } from '%s/download.js';
const v = await checkForProUpdate('cb_fake', 'stable');
console.log('  update available:', v === null ? 'NO (frozen)' : v);
""" % NPM_DIST], env={**os.environ,
                      "CLOAKBROWSER_AUTO_UPDATE": "false",
                      "CLOAKBROWSER_VERSION": pinned,
                      "CLOAKBROWSER_LICENSE_API": "http://127.0.0.1:1"})
    print(r.stdout.rstrip() or r.stderr.rstrip())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", help="version to pin (default: detected installed)")
    ap.add_argument("--unfreeze", action="store_true")
    ap.add_argument("--status", action="store_true")
    args = ap.parse_args()

    installed = detect_installed()
    if not installed:
        sys.exit("no chromium-*-pro build under ~/.cloakbrowser")
    pinned = args.version or installed

    if args.status:
        verify(pinned)
        return

    if args.unfreeze:
        print("=== UNFREEZE ===")
        unpatch_license_js()
        for f in [CACHE / f"latest_pro_version_{PLATFORM}",
                  CACHE / f".last_pro_version_resolution_{PLATFORM}"]:
            run(["chattr", "-i", str(f)])
        run(["chattr", "-i", str(CACHE / f"chromium-{pinned}-pro")])
        for rc in RC_FILES:
            if rc.exists() and ENV_BLOCK_BEGIN in rc.read_text(errors="ignore"):
                txt = re.sub(re.escape(ENV_BLOCK_BEGIN) + r".*?" +
                             re.escape(ENV_BLOCK_END) + r"\n?", "", rc.read_text(), flags=re.S)
                rc.write_text(txt)
                print(f"  env block removed <- {rc}")
        print("unfrozen")
        return

    print(f"=== FREEZE at {pinned} ===")
    print("[L1] env vars")
    write_env_block(pinned)
    print("[L2] version markers")
    pin_markers(pinned)
    print("[L3] offline update resolver")
    patch_license_js(pinned)
    print("[L4] binary + dir lock")
    repair_binary(pinned)
    lock_version_dir(pinned)
    verify(pinned)


if __name__ == "__main__":
    main()
