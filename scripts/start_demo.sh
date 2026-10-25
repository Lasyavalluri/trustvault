#!/usr/bin/env bash
set -eu

database_path="${TRUSTVAULT_DATABASE:-${TRUSTVAULT_DATA_DIR:-.data}/trustvault.sqlite3}"
if [ ! -f "$database_path" ]; then
    python main.py seed-demo
fi

exec uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers 1
