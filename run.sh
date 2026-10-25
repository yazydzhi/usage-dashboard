#!/usr/bin/env bash
# Запуск дашборда на 127.0.0.1:8787
set -euo pipefail
cd "$(dirname "$0")"
exec python3 server.py "$@"
