# CloakBrowser Pro — Session Limit Bypass

**Target:** `~/.cloakbrowser/chromium-152.0.7977.82.2-pro/chrome` (519 MB, ELF, not stripped)
**Goal:** Remove the 1-concurrent-session limit on the free license so N browsers can run in parallel.
**Status:** DONE — verified 8/8 concurrent sessions, zero license traffic, no exit codes.

---

## 1. Architecture of the enforcement

CloakBrowser ships two pieces:

| Piece | Location | Role |
|---|---|---|
| Python wrapper | `~/.local/lib/python3.14/site-packages/cloakbrowser/` | Resolves license key, downloads the Pro binary, injects env vars. **No enforcement here.** |
| Pro Chromium binary | `~/.cloakbrowser/chromium-<ver>-pro/chrome` | Contains `ungoogled::LicenseRuntime` — the actual gate. |

The wrapper's only "gate" is `_pro_binary_ready()`: `path.exists() and _is_executable()`.
There is **no hash/signature check at launch time** — the Ed25519 signature is only
verified once, when the archive is *downloaded*. A patched binary on disk launches fine.

### LicenseRuntime protocol

Discovered by disassembly (`nm` + `objdump`, symbols intact):

```
Start(factory, factory)     @ 0xcfee940   called once from ChromeBrowserMainParts::PreMainMessageLoopRun
End()                       @ 0xcfef670   called from browser_shutdown::OnShutdownStarting
SendHeartbeat()             @ 0xcff1f90   scheduled from the start response
OnResponse(type, body)      @ 0xcff0230   parses JSON, verifies lease, exits on denial
```

**Request** (POST, JSON, observed live against a local listener):

```json
POST /api/license/session/start
{"install_id":"<uuid>","instance_id":"<uuid>","license_key":"cb_...",
 "platform":"linux-x64","version":"152.0.7977.82"}
```

API base URL is overridable via `CLOAKBROWSER_LICENSE_API` (default `https://cloakbrowser.dev`).
Other endpoints: `/api/license/session/end`, `/api/license/session/heartbeat`.

**Response fields** (from string xrefs in the binary): `valid`, `error`, `token`,
`heartbeat_interval_seconds`, `lease_ttl_seconds`, `expires_at`, `lease_id`,
`license_key_hash`.

**Lease token:** the server signs a token with Ed25519; the binary verifies it with a
public key hardcoded at `.rodata+0x2bb71ab`:

```
a9 97 50 ac 24 a6 6f cf 68 54 03 27 58 85 9e 79
84 87 0a 32 e4 dc 01 51 bb 78 f4 df 06 a4 f6 b5
```

`ED25519_verify` is called at 4 sites inside LicenseRuntime (`0xcfefcd4`, `0xcff0f1a`,
`0xcff1820`, `0xcff22c3`). This means **a fake license server alone cannot work** —
the response token must be signed with CloakHQ's private key.

**Exit codes** (all inside LicenseRuntime, via `base::Process::TerminateCurrentProcessImmediately`):

| Code | Meaning | Address |
|---|---|---|
| 76 | session limit reached | `0xcff1cf4` (OnResponse), also `0xcff1c81` write path |
| 77 | license invalid/expired | `0xcff1e1c` |
| 78 | license server unreachable | `0xcfef636` (Start), `0xcff1d80` (OnResponse) |
| 79 | `~/.cloakbrowser` not writable | `0xcfef64a` |

Verified empirically *before* patching:

- Session 1 launches and holds a seat.
- Session 2 with the same key: `DevTools listening ...` then **exit 78** (server sees the
  seat cap and denies; with a real network the code is 76).
- Launch with **no key at all**: also exit 78 — enforcement runs unconditionally.

---

## 2. The patch

Only 4 sites in the whole binary reference the `LicenseRuntime` singleton
(`0x88080b0`, `0x8808162` in boot; `0x9517350`, `0x951752a` in shutdown), and nothing
else reads license state. So the cleanest fix is to neuter the two entry points:

```asm
; LicenseRuntime::Start  (0xcfee940)  ->  xor eax,eax; ret
; LicenseRuntime::End    (0xcfef670)  ->  xor eax,eax; ret
```

Effects:

- No `/session/start` request → the server never registers a seat → **no cap to hit**.
- No heartbeat scheduling (it is armed inside Start).
- No response parsing, no Ed25519 check, no exit 76/77/78/79.
- `End()` no-op → no `/session/end` request at shutdown.
- All Pro fingerprint patches (canvas, WebGL, GPU, screen, WebRTC, fonts, …) untouched.

**Script:** `patch_cloakbrowser.py` — resolves addresses by symbol name (`nm`), so it
survives version bumps as long as the mangled symbols exist. Refuses to patch if the
prologue doesn't match. Keeps `chrome.orig-backup` for restore.

```
python3 patch_cloakbrowser.py            # patch (default: newest *-pro binary)
python3 patch_cloakbrowser.py --restore  # revert
```

---

## 3. Verification (all after patch)

| Test | Result |
|---|---|
| Single launch, 30 s | exit 124 (killed by timeout) — no license exit |
| Single launch, 100 s | still alive, **0 requests** logged by the local listener |
| **3 concurrent** sessions, same key | 3/3 exit 124 → **PASS** |
| **8 concurrent** sessions, same key | 8/8 exit 124 → **PASS** |
| 2 concurrent via `cloakbrowser.launch()` (Playwright wrapper) | both `LAUNCH_OK` + `CLOSED_OK`, exit 0 |
| Real page load (`--dump-dom https://example.com`) | full DOM rendered, exit 0 |
| License server traffic after patch | **zero** (listener log empty) |

`exit 124` = the process was still running when `timeout` killed it — i.e. it never
self-terminated with a license denial.

---

## 4. Operational notes

- **Re-apply after update.** `cloakbrowser update` / `cloakbrowser install` downloads a
  fresh binary into a new `chromium-<ver>-pro/` directory; run `patch_cloakbrowser.py`
  again afterwards (the script auto-targets the newest one).
- The wrapper's `info` command still prints `Sessions: 0/1` — that number comes from the
  *wrapper* querying the server directly (`/api/license/session/count`), purely
  cosmetic; it does not gate launches.
- `cloakbrowser doctor` / `info` and the Playwright API are unaffected.
- Restore path: `chrome.orig-backup` next to the binary, or `--restore`.

## 5. Files

```
~/Documents/cloakbrowser-re/
├── REPORT.md               this document
├── patch_cloakbrowser.py   symbol-driven patcher (patch + restore)
├── fake_license_server.py  local listener used to capture the wire protocol
└── multitest.sh            N-concurrent-session harness (exit-code verdicts)
```
