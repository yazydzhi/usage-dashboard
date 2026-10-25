#!/usr/bin/env python3
"""Дашборд лимитов и балансов по подключениям.

Запуск:
    python3 server.py                 # http://127.0.0.1:8787
    python3 server.py --port 9000
    python3 server.py --host 0.0.0.0  # для доступа из локальной сети

Эндпоинты:
    GET /                — страница дашборда
    GET /api/usage       — JSON со всеми карточками (кэш N секунд)
    GET /api/usage?force=1 — принудительное обновление
    GET /api/health      — статус сервера

Секреты читаются только локально из secrets.env и системных хранилищ
(keychain macOS, файлы конфигов CLI) и в браузер не передаются.
"""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import providers

ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(ROOT, "config.json")

_lock = threading.Lock()
_cache: dict = {"payload": None, "at": 0.0}


def load_config() -> dict:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def load_secrets(config: dict) -> dict[str, str]:
    rel = config.get("secrets_file") or "secrets.env"
    path = rel if os.path.isabs(rel) else os.path.join(ROOT, rel)
    return providers.read_env_file(path)


def get_payload(force: bool = False) -> dict:
    config = load_config()
    ttl = float(config.get("cache_seconds", 25))
    with _lock:
        fresh = _cache["payload"] is not None and (time.time() - _cache["at"]) < ttl
        if fresh and not force:
            payload = dict(_cache["payload"])
            payload["cached"] = True
            payload["age_seconds"] = round(time.time() - _cache["at"], 1)
            return payload

    secrets = load_secrets(config)
    payload = providers.collect(config, secrets)
    payload["cached"] = False
    payload["age_seconds"] = 0
    with _lock:
        _cache["payload"] = payload
        _cache["at"] = time.time()
    return payload


class Handler(BaseHTTPRequestHandler):
    server_version = "UsageDashboard/1.0"

    def log_message(self, fmt: str, *args) -> None:  # тише в консоли
        if os.environ.get("DASHBOARD_VERBOSE"):
            super().log_message(fmt, *args)

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            index = os.path.join(ROOT, "web", "index.html")
            try:
                with open(index, "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError as exc:
                self._send(500, f"нет web/index.html: {exc}".encode(), "text/plain; charset=utf-8")
            return

        if path == "/api/health":
            self._json(200, {"ok": True, "uptime": round(time.time() - STARTED, 1)})
            return

        if path == "/api/usage":
            force = parse_qs(parsed.query).get("force", ["0"])[0] in ("1", "true", "yes")
            try:
                self._json(200, get_payload(force=force))
            except Exception as exc:  # noqa: BLE001
                self._json(500, {"error": str(exc), "cards": []})
            return

        self._json(404, {"error": "not found"})


STARTED = time.time()


def main() -> None:
    parser = argparse.ArgumentParser(description="Дашборд лимитов подключений")
    parser.add_argument("--port", type=int, default=int(os.environ.get("DASHBOARD_PORT", 8787)))
    parser.add_argument("--host", default=os.environ.get("DASHBOARD_HOST", "127.0.0.1"))
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.daemon_threads = True
    print(f"Дашборд: http://{args.host}:{args.port}  (Ctrl+C — остановить)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nостановлено")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
