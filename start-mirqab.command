#!/bin/bash
# MIRQAB launcher for macOS: sets up a virtual environment, creates real accounts on first run, starts the server.
cd "$(dirname "$0")"
for b in /opt/homebrew/bin/brew /usr/local/bin/brew "$HOME/.homebrew/bin/brew"; do [ -x "$b" ] && eval "$("$b" shellenv)" && break; done
echo "== MIRQAB =="
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3 /opt/homebrew/bin/python3 "$HOME/.homebrew/bin/python3"; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then echo "Python 3.10+ not found. Install from https://www.python.org/downloads/"; read -p "Press Enter to close"; exit 1; fi
echo "Using $($PY --version)"
if [ ! -d .venv ]; then "$PY" -m venv .venv || { read -p "venv failed. Press Enter"; exit 1; }; fi
source .venv/bin/activate
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements.txt || { read -p "Install failed. Press Enter"; exit 1; }
if [ ! -f .env ]; then
  cp .env.example .env
  KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
  sed -i '' "s|^MIRQAB_SECRET_KEY=.*|MIRQAB_SECRET_KEY=$KEY|" .env
fi
if [ ! -f ACCOUNTS.txt ]; then
  : > ACCOUNTS.txt
  for spec in admin:admin; do
    u=${spec%%:*}; r=${spec##*:}
    p=$(python -c "import secrets;print(secrets.token_urlsafe(9)+'7a')")
    MIRQAB_NEW_USER_PASSWORD="$p" python -m backend.app.cli create-user --username "$u" --role "$r" >/dev/null 2>&1 && echo "$u  $p" >> ACCOUNTS.txt
  done
  chmod 600 ACCOUNTS.txt
  echo "Accounts created (saved in ACCOUNTS.txt):"; cat ACCOUNTS.txt
fi
# one sign-in account (admin has every permission); older installs had three
if [ ! -f .single-account ] && python -m backend.app.cli single-account >/dev/null 2>&1; then
  grep '^admin ' ACCOUNTS.txt > ACCOUNTS.tmp 2>/dev/null && cat ACCOUNTS.tmp > ACCOUNTS.txt; rm -f ACCOUNTS.tmp 2>/dev/null
  : > .single-account
fi
grep -q '^MIRQAB_RADAR_ENABLED=' .env || echo 'MIRQAB_RADAR_ENABLED=true' >> .env
for p in 8765 8766 8767 8780 8790; do
  pid=$(lsof -ti tcp:$p -sTCP:LISTEN 2>/dev/null)
  if [ -n "$pid" ] && ps -p $pid -o command= | grep -q "backend.app.main"; then
    kill $pid; echo "Restarting: stopped previous MIRQAB on port $p"
    # wait until the port is really free so the address stays the same after a restart
    for i in $(seq 1 30); do lsof -ti tcp:$p -sTCP:LISTEN >/dev/null 2>&1 || break; sleep 0.5; done
  fi
done
command -v tesseract >/dev/null || echo "Note: Tesseract not installed — screenshot OCR disabled (brew install tesseract tesseract-lang)."
PORT=$(python -c "
import socket
for p in [8765, 8766, 8767, 8780, 8790]:
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('127.0.0.1', p)); s.close(); print(p); break
    except OSError:
        s.close()
")
echo "Starting on http://127.0.0.1:$PORT  (close this window to stop)"
exec python -m uvicorn --factory backend.app.main:create_app --host 127.0.0.1 --port "$PORT"
