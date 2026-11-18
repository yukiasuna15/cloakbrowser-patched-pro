# CloakBrowser — Patched Pro Binary (session-limit bypass)

Neutralized `ungoogled::LicenseRuntime` in the **CloakBrowser Pro** Chromium binary, removing
the 1-concurrent-session limit enforced by the free license. The patched binary runs any
number of parallel instances, makes **zero** license traffic, and never self-terminates with
exit 76/77/78/79.

> ⚠️ Research / interoperability. The Ed25519 response signature is only verified at
> **download** time — not at launch — so a patched binary on disk runs fine. No CloakHQ
> private key is required (and none is used).

---

## What's here

| Path | What it is |
|---|---|
| `scripts/patch_cloakbrowser_generic.py` | **Main patcher.** Stripped-binary safe — locates the runtime functions via `.rodata` string xrefs, no symbols needed. Supports `--dry-run` and `--restore`. |
| `scripts/patch_cloakbrowser_symbol.py` | Symbol-driven variant (`nm`-based) for unstripped builds (e.g. 152.x). |
| `scripts/cloak_guard.py` | Wrapper/guard so a fresh `cloakbrowser update` gets re-patched automatically. |
| `scripts/freeze_cloakbrowser.py`, `scripts/freeze.sh` | Pin the version + block auto-update / license API reach-out. |
| `scripts/final_check.mjs` | Post-patch smoke test. |
| `docs/REPORT-152-oldstring.md` | Full reverse-engineering writeup: enforcement architecture, wire protocol, ELF offsets, and the N-concurrent session test matrix. |
| `checksums.txt` | SHA-256 of every tracked file. |

**Patched binary** is attached to the [Releases](../../releases) page (336 MB, over git's 100 MB blob limit).

---

## Binary version patched

```
CloakBrowser Pro 156.0.8078.47.1   (linux-x64)
chrome      : 351,767,880 bytes   sha256 075b51c0…  ← patched
orig-backup : 351,767,880 bytes   sha256 37c2b771…
```

Verified patch sites (file offsets, `.text`):

| Function | vaddr | file offset | orig | patched |
|---|---|---|---|---|
| `LicenseRuntime::Start` | `0xde79ac0` | `0xde78ac0` | `55 48 89 e5` | `31 c0 c3 90` |
| `LicenseRuntime::End`   | `0xde7bad0` | `0xde7aad0` | `55 48 89 e5` | `31 c0 c3 90` |

`31 c0 c3 90` = `xor eax,eax ; ret ; nop` — both entry points return immediately.

---

## How the enforcement works (short)

The Pro binary embeds `ungoogled::LicenseRuntime`:

- `Start()` fires once from `ChromeBrowserMainParts::PreMainMessageLoopRun` and POSTs
  `/api/license/session/start` with the install id + license key.
- The server returns a lease that is **Ed25519-signed**; the binary verifies it in-binary.
- `SendHeartbeat()` and `End()` keep/close the seat.
- On denial it calls `TerminateCurrentProcessImmediately` with codes
  `76` (seat cap) · `77` (invalid/expired) · `78` (unreachable) · `79` (dir not writable).

Neutering `Start` and `End` removes the request, the heartbeat, the signature check, and
every exit path — while leaving all of the Pro fingerprint patches (canvas, WebGL, GPU,
screen, WebRTC, fonts, …) untouched.

Full details in [`docs/REPORT-152-oldstring.md`](docs/REPORT-152-oldstring.md).

---

## Usage

```bash
# 1. install the unpatched Pro binary however you normally do, then:
python3 scripts/patch_cloakbrowser_generic.py          # newest *-pro binary
python3 scripts/patch_cloakbrowser_generic.py --dry-run # show what it would patch
python3 scripts/patch_cloakbrowser_generic.py --restore # revert from chrome.orig-backup
```

The patcher keeps a `chrome.orig-backup` next to the binary and refuses to patch if the
prologue doesn't match — so it fails safe on layout changes.

Requires `pyelftools`: `pip install pyelftools`.

---

## Re-apply after update

`cloakbrowser update` downloads a fresh binary into a **new** `chromium-<ver>-pro/` directory.
The old patch does **not** carry over — run the patcher again afterwards (it auto-targets the
newest one). `cloak_guard.py` + `freeze.sh` automate this.
