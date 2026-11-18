#!/usr/bin/env bash
# CloakBrowser freeze: pin version + disable auto-update + kill network update check
set -e

RC="$HOME/.cloakbrowser"
PIN="156.0.8078.47.1"

echo "=== 1. ENV VARS (global, all shells) ==="
grep -q 'CLOAKBROWSER_AUTO_UPDATE' ~/.bashrc 2>/dev/null || cat >> ~/.bashrc <<'EOF'

# --- CloakBrowser freeze ---
export CLOAKBROWSER_AUTO_UPDATE=false
export CLOAKBROWSER_VERSION=156.0.8078.47.1
export CLOAKBROWSER_LICENSE_API=http://127.0.0.1:1
EOF
echo "written to ~/.bashrc"

echo
echo "=== 2. PIN latest version markers to installed build ==="
echo "$PIN" > "$RC/latest_pro_version_linux-x64"
echo "{\"version\":\"$PIN\",\"requested_channel\":\"stable\",\"resolved_channel\":\"stable\",\"fallback\":false}" > "$RC/.last_pro_version_resolution_linux-x64"

echo
echo "=== 3. Lock version markers read-only (chattr) ==="
chattr +i "$RC/latest_pro_version_linux-x64" "$RC/.last_pro_version_resolution_linux-x64" 2>/dev/null \
  && echo "immutable set" || echo "chattr unavailable (need root) - using mtime freeze instead"

echo
echo "=== 4. Refresh mtime so 1h cache never expires ==="
touch "$RC/.last_pro_version_check_linux-x64" "$RC/.last_pro_version_resolution_linux-x64"

echo
echo "=== 5. Verify binary still patched ==="
CH="$RC/chromium-$PIN-pro/chrome"
python3 - "$CH" <<'PY'
import sys
p=sys.argv[1]
d=open(p,'rb').read()
# patched sites from earlier run
for va,off in [(0xde79ac0,0xde78ac0),(0xde7bad0,0xde7aad0)]:
    print(f"  {va:#x}: {d[off:off+4].hex()} {'PATCHED' if d[off:off+3]==bytes.fromhex('31c0c3') else 'NOT PATCHED'}")
PY
