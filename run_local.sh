#!/usr/bin/env sh
set -eu
: "${PTO_SETUP_TOKEN:=local-alpha-setup-change-me}"
export PTO_SETUP_TOKEN
export PYTHONPATH="$(pwd)"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
