#!/bin/bash
# Adds or replaces MIRQAB's API keys in .env without showing them on screen.
# Leave a prompt empty to keep the current value.
cd "$(dirname "$0")" || exit 1
umask 077
echo "== MIRQAB · API keys =="
[ -f .env ] || cp .env.example .env
chmod 600 .env

set_key () {   # $1 = variable name, $2 = label
  echo
  echo "Paste your $2 and press Enter (it will not be shown; empty = keep current):"
  read -rs KEY; echo
  [ -z "$KEY" ] && { echo "  $1 unchanged."; return; }
  case "$KEY" in *[!A-Za-z0-9_-]*) echo "  That doesn't look like an API key — $1 unchanged."; return;; esac
  grep -v "^$1=" .env > .env.tmp
  printf '%s=%s\n' "$1" "$KEY" >> .env.tmp
  cat .env.tmp > .env && rm -f .env.tmp
  echo "  $1 saved."
  [ "$1" = "OPENAI_API_KEY" ] && OPENAI_SET=1
}

set_key OPENAI_API_KEY "OpenAI API key (deepfake image review + AI message analysis)"

if [ -n "$OPENAI_SET" ] && ! grep -qE '^MIRQAB_LLM_PROVIDER=(anthropic|openai)' .env; then
  grep -v '^MIRQAB_LLM_PROVIDER=' .env > .env.tmp
  echo 'MIRQAB_LLM_PROVIDER=openai' >> .env.tmp
  cat .env.tmp > .env && rm -f .env.tmp
  echo "  AI message analysis switched to OpenAI."
fi
chmod 600 .env
echo
echo "Done. Restart MIRQAB (double-click start-mirqab.command) to apply."
read -p "Press Enter to close"
