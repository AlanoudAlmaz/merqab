#!/bin/bash
# Installs Tesseract OCR (English + Arabic) for MIRQAB screenshot analysis, then restarts MIRQAB.
cd "$(dirname "$0")"
echo "== MIRQAB: installing OCR =="
BREW=""
for b in brew /opt/homebrew/bin/brew /usr/local/bin/brew "$HOME/.homebrew/bin/brew"; do
  if command -v "$b" >/dev/null 2>&1; then BREW="$b"; break; fi
done
if [ -z "$BREW" ]; then echo "Homebrew not found. Install it from https://brew.sh then run this again."; read -p "Press Enter to close"; exit 1; fi
echo "Using Homebrew: $BREW"
eval "$("$BREW" shellenv)"
command -v tesseract >/dev/null || yes | HOMEBREW_NO_ASK=1 HOMEBREW_NO_INSTALL_CLEANUP=1 "$BREW" install tesseract || { read -p "Install failed. Press Enter"; exit 1; }
TESSDIR="$("$BREW" --prefix)/share/tessdata"
if [ ! -f "$TESSDIR/ara.traineddata" ]; then
  echo "Downloading Arabic language data..."
  curl -fL --retry 2 -o "$TESSDIR/ara.traineddata" https://github.com/tesseract-ocr/tessdata_fast/raw/main/ara.traineddata || { read -p "Arabic download failed. Press Enter"; exit 1; }
fi
echo "Installed languages:"; tesseract --list-langs
# stop the running MIRQAB so it restarts with OCR enabled
for p in 8765 8766 8767 8780 8790; do
  pid=$(lsof -ti tcp:$p -sTCP:LISTEN 2>/dev/null)
  if [ -n "$pid" ] && ps -p $pid -o command= | grep -q "backend.app.main"; then kill $pid; echo "Stopped old MIRQAB on port $p"; fi
done
sleep 2
exec ./start-mirqab.command
