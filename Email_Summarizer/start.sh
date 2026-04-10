#!/bin/sh
set -eu

PORT="${PORT:-8000}"

exec python3 -m uvicorn dashboard_api:app --host 0.0.0.0 --port "$PORT"
