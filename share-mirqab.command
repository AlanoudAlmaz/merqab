#!/bin/bash
# Keeps MERQAB's public link alive: checks it every 20 s and, if it stops answering for about a minute,
# restarts the Cloudflare tunnel and writes the new link to PUBLIC-LINK.txt. Keeps the Mac awake while open.
cd "$(dirname "$0")" || exit 1
caffeinate -dimsu -w $$ &
BIN="$(command -v cloudflared || echo .tools/cloudflared)"
echo "== MERQAB keep-online =="
echo "Keep this window open. Keep the Mac plugged in with the lid open."
start_tunnel() {
  pkill -f "cloudflared tunnel --no-autoupdate --url http://127.0.0.1" 2>/dev/null
  sleep 3; rm -f PUBLIC-LINK.txt
  ( "$BIN" tunnel --no-autoupdate --url "http://127.0.0.1:8765" 2>&1 | while IFS= read -r line; do
      url=$(echo "$line" | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com')
      if [ -n "$url" ] && [ ! -f PUBLIC-LINK.txt ]; then echo "$url" > PUBLIC-LINK.txt; echo "$(date '+%H:%M') NEW public link: $url"; fi
    done ) &
}
[ -f PUBLIC-LINK.txt ] || start_tunnel
fails=0
while true; do
  if ! curl -s -m 5 -o /dev/null "http://127.0.0.1:8765/api/health"; then
    echo "$(date '+%H:%M') MERQAB server is not running — double-click start-mirqab.command"
  else
    L=$(cat PUBLIC-LINK.txt 2>/dev/null)
    if [ -n "$L" ] && [ "$(curl -s -m 15 -o /dev/null -w '%{http_code}' "$L/api/health")" = "200" ]; then
      [ $fails -gt 0 ] && echo "$(date '+%H:%M') link OK: $L"; fails=0
    else
      fails=$((fails+1)); echo "$(date '+%H:%M') public link not answering ($fails/3)"
      if [ $fails -ge 3 ]; then echo "$(date '+%H:%M') restarting the tunnel…"; start_tunnel; fails=0; sleep 25; fi
    fi
  fi
  sleep 20
done
