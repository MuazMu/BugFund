#!/usr/bin/env bash
# =============================================================================
# BugFund CRS — local dev runner.
#
# Brings up the control plane API, the Celery worker, and Celery beat in the
# FOREGROUND as backgrounded processes, with a trap that cleans them all up
# on exit (Ctrl-C, kill, or normal return).
#
# Requires a populated `.env` and an active virtualenv. Defaults to the
# POSIX layout (`.venv/bin/python`). Windows users: use the venv python at
# `./.venv/Scripts/python` instead, or run the three processes manually:
#
#     ./.venv/Scripts/python -m uvicorn control_plane.api.main:app --reload --port 8000
#     ./.venv/Scripts/python -m celery -A control_plane.tasks.celery_app worker -l info -Q campaigns,sandbox
#     ./.venv/Scripts/python -m celery -A control_plane.tasks.celery_app beat -l info
#
# (This file is intentionally bash/POSIX; on Windows run it under Git Bash or WSL.)
# =============================================================================
set -euo pipefail

# Pick the venv python. Override by setting PY=... when invoking:
#     PY=./.venv/Scripts/python ./scripts/run_dev.sh
PY="${PY:-./.venv/bin/python}"
if [ ! -x "$PY" ] && [ ! -f "$PY" ]; then
    echo "[run_dev] Python not found at $PY" >&2
    echo "[run_dev] Create a venv (python -m venv .venv) and pip install -e \".[dev]\"," >&2
    echo "[run_dev] or set PY=<path-to-python> (Windows: PY=./.venv/Scripts/python)." >&2
    exit 1
fi

PIDS=()

cleanup() {
    echo
    echo "[run_dev] Cleaning up child processes..."
    for pid in "${PIDS[@]:-}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    # Give them a moment, then force.
    sleep 1
    for pid in "${PIDS[@]:-}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT INT TERM

echo "[run_dev] Starting API on :8000 ..."
"$PY" -m uvicorn control_plane.api.main:app --reload --host 0.0.0.0 --port 8000 &
PIDS+=("$!")

echo "[run_dev] Starting Celery worker (queues: campaigns,sandbox) ..."
"$PY" -m celery -A control_plane.tasks.celery_app worker -l info -Q campaigns,sandbox &
PIDS+=("$!")

echo "[run_dev] Starting Celery beat ..."
"$PY" -m celery -A control_plane.tasks.celery_app beat -l info &
PIDS+=("$!")

echo "[run_dev] All three processes are up. Ctrl-C to stop all of them."

# Wait for any child to exit; the trap handles cleanup.
wait
