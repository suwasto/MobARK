#!/usr/bin/env bash
# M10 Phase F - render the GitHub social-preview PNG (~1280x640) from the
# dark-background header art. Uses headless Chrome (same approach as the e2e
# screenshots): load an HTML page with the dark background + the vendored
# brand SVG, screenshot the viewport, write site/assets/mobark-social-preview.png.
#
# Usage:  scripts/render_social_preview.sh
#   CHROME=/path/to/chrome  - override the Chrome binary (auto-detected on macOS/Linux).
#   OUT=site/assets/mobark-social-preview.png - override the output path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${OUT:-$ROOT/site/assets/mobark-social-preview.png}"
HTML="$ROOT/site/assets/demo/social-preview.html"

if command -v google-chrome >/dev/null 2>&1; then
  CHROME="$(command -v google-chrome)"
elif command -v google-chrome-stable >/dev/null 2>&1; then
  CHROME="$(command -v google-chrome-stable)"
elif [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
  CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
elif command -v chromium >/dev/null 2>&1; then
  CHROME="$(command -v chromium)"
else
  echo "no Chrome/Chromium found - set CHROME=/path/to/chrome" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"

"$CHROME" --headless --disable-gpu --no-sandbox \
  --hide-scrollbars --force-device-scale-factor=1 \
  --window-size=1280,640 \
  --screenshot="$OUT" "file://$HTML" >/dev/null 2>&1

echo "social preview written: $OUT"
