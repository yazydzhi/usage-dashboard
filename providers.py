"""Адаптеры провайдеров для дашборда лимитов.

Каждый адаптер возвращает нормализованную карточку:

    {
        "id": "claude",
        "name": "Claude",
        "subtitle": "Anthropic · подписка",
        "plan": "Max 20x" | None,
        "status": "ok" | "warn" | "error" | "unconfigured",
        "error": None | "текст",
        "balance": {"amount": 3.93, "currency": "USD"} | None,
        "windows": [
            {"label": "Неделя", "percent": 41.0, "resets_at": "ISO" | None,
             "detail": "…", "severity": "normal"}
        ],
        "lines": ["…"],          # произвольные детали строками
        "source": "api.anthropic.com/api/oauth/usage",
        "links": [{"label": "Консоль", "url": "https://…"}],
    }

Секреты читаются только на сервере и никогда не попадают в JSON для браузера.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

HOME = os.path.expanduser("~")
DEFAULT_TIMEOUT = 15.0
UA = "usage-dashboard/1.0"

CURSOR_DB = os.path.join(
    HOME, "Library/Application Support/Cursor/User/globalStorage/state.vscdb"
)
CURSOR_USAGE_URL = "https://api2.cursor.sh/aiserver.v1.DashboardService/GetCurrentPeriodUsage"
CURSOR_PROFILE_URL = "https://api2.cursor.sh/auth/full_stripe_profile"


# --------------------------------------------------------------------------- #
#  Инфраструктура
# --------------------------------------------------------------------------- #


class SecretMissing(Exception):
    """Ключ не найден — карточка показывается как «не настроено»."""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _http_json(
    url: str,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    body: Any = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Any:
    data = None
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:  # noqa: PERF203
        body = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"HTTP {exc.code}: {_error_message(body)}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"сеть недоступна ({exc.reason})") from None
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(f"ответ не JSON: {_short(raw)}") from None


def _short(text: str, limit: int = 220) -> str:
    text = re.sub(r"\s+", " ", str(text)).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _error_message(body: str) -> str:
    """Достаёт человекочитаемое сообщение из JSON-ошибки API."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return _short(body, 160)
    node: Any = data
    for key in ("error", "detail", "data", "response"):
        if isinstance(node, dict) and isinstance(node.get(key), dict):
            node = node[key]
    for key in ("message", "msg", "detail", "code", "error"):
        value = node.get(key) if isinstance(node, dict) else None
        if isinstance(value, str) and value:
            return _short(value, 160)
    return _short(body, 160)


_EXPIRED_HINTS = ("expired", "revoked", "invalid_grant", "api_key_expired")


def humanize_error(text: str) -> str:
    """Переводит технические ошибки в понятную причину + что делать."""
    raw = str(text or "")
    low = raw.lower()
    if any(hint in low for hint in _EXPIRED_HINTS):
        return "Ключ истёк или отозван — выпусти новый в консоли сервиса и обнови secrets.env."
    if "http 401" in low:
        return "Не авторизован (401) — проверь, что ключ верный и активный."
    if "http 403" in low:
        return "Доступ запрещён (403) — у ключа нет прав на этот эндпоинт."
    if "http 404" in low:
        return "Эндпоинт не найден (404) — возможно, API изменился."
    if "http 429" in low:
        return "Слишком много запросов (429) — подожди минуту."
    if "http 5" in low:
        return f"Ошибка на стороне сервиса: {_short(raw, 140)}"
    return _short(raw, 240)



def read_env_file(path: str) -> dict[str, str]:
    """Простой парсер .env: KEY=VALUE, кавычки и комментарии."""
    out: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip().removeprefix("export ").strip()
                value = value.strip().strip('"').strip("'")
                if key and value:
                    out[key] = value
    except OSError:
        pass
    return out


def read_json_file(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def keychain_password(service: str) -> str | None:
    if not shutil.which("security"):
        return None
    try:
        res = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-w"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return res.stdout.strip() or None


def sqlite_value(db_path: str, key: str) -> str | None:
    if not os.path.exists(db_path):
        return None
    uri = f"file:{urllib.parse.quote(db_path)}?mode=ro&immutable=1"
    try:
        con = sqlite3.connect(uri, uri=True, timeout=5)
    except sqlite3.Error:
        return None
    try:
        row = con.execute("SELECT value FROM ItemTable WHERE key = ?", (key,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        con.close()
    if not row:
        return None
    value = row[0]
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value).strip() or None


def first_env(names: list[str], extra_files: list[str] | None = None) -> str | None:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    for path in extra_files or []:
        value = read_env_file(path).get(names[0], "").strip()
        if value:
            return value
        for name in names:
            value = read_env_file(path).get(name, "").strip()
            if value:
                return value
    return None


def iso_from_epoch(value: Any) -> str | None:
    try:
        num = float(value)
    except (TypeError, ValueError):
        return None
    if num > 1e11:  # миллисекунды
        num /= 1000.0
    try:
        return datetime.fromtimestamp(num, timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None


def window(
    label: str,
    percent: Any,
    resets_at: Any = None,
    detail: str | None = None,
    severity: str | None = None,
) -> dict:
    try:
        pct = max(0.0, min(100.0, float(percent)))
    except (TypeError, ValueError):
        pct = 0.0
    reset = resets_at if isinstance(resets_at, str) else iso_from_epoch(resets_at)
    return {
        "label": label,
        "percent": round(pct, 1),
        "resets_at": reset,
        "detail": detail,
        "severity": severity,
    }


def money(amount: float) -> str:
    return f"${amount:,.2f}"


def card(
    pid: str,
    name: str,
    subtitle: str,
    status: str = "ok",
    *,
    plan: str | None = None,
    balance: dict | None = None,
    windows: list[dict] | None = None,
    lines: list[str] | None = None,
    source: str = "",
    links: list[dict] | None = None,
    error: str | None = None,
) -> dict:
    windows = windows or []
    if status == "ok" and any((w.get("percent") or 0) >= 80 for w in windows):
        status = "warn"
    return {
        "id": pid,
        "name": name,
        "subtitle": subtitle,
        "plan": plan,
        "status": status,
        "error": humanize_error(error) if error else None,
        "balance": balance,
        "windows": windows,
        "lines": lines or [],
        "source": source,
        "links": links or [],
        "updated_at": now_iso(),
    }


def unconfigured(pid: str, name: str, subtitle: str, hint: str) -> dict:
    return card(pid, name, subtitle, "unconfigured", error=hint)


# --------------------------------------------------------------------------- #
#  Claude (Anthropic) — /api/oauth/usage по OAuth-токену Claude Code
# --------------------------------------------------------------------------- #

_ANTHROPIC_LIMIT_LABELS = {
    "session": "Сессия (5 ч)",
    "five_hour": "Сессия (5 ч)",
    "weekly_all": "Неделя",
    "weekly": "Неделя",
    "seven_day": "Неделя",
    "weekly_opus": "Неделя · Opus",
    "seven_day_opus": "Неделя · Opus",
    "weekly_sonnet": "Неделя · Sonnet",
    "seven_day_sonnet": "Неделя · Sonnet",
    "weekly_oauth_apps": "Неделя · другие приложения",
}


def _anthropic_token() -> str:
    raw = keychain_password("Claude Code-credentials")
    payload = read_json_file(os.path.join(HOME, ".claude/.credentials.json"))
    if raw:
        try:
            payload = json.loads(raw) or payload
        except json.JSONDecodeError:
            pass
    token = ((payload or {}).get("claudeAiOauth") or {}).get("accessToken", "")
    if not token:
        raise SecretMissing(
            "Нет OAuth-токена Claude Code (keychain «Claude Code-credentials»). "
            "Войди: claude → /login."
        )
    return token


def fetch_claude() -> dict:
    pid, name, sub = "claude", "Claude", "Anthropic · подписка"
    try:
        token = _anthropic_token()
        payload = _http_json(
            "https://api.anthropic.com/api/oauth/usage",
            headers={
                "Authorization": f"Bearer {token}",
                "anthropic-beta": "oauth-2025-04-20",
                "User-Agent": "claude-cli/2.1.0",
            },
        )
    except SecretMissing as exc:
        return unconfigured(pid, name, sub, str(exc))
    except Exception as exc:  # noqa: BLE001
        return card(pid, name, sub, "error", source="api.anthropic.com", error=_short(exc))

    windows: list[dict] = []
    for item in payload.get("limits") or []:
        kind = str(item.get("kind") or "")
        label = _ANTHROPIC_LIMIT_LABELS.get(kind, kind or "Лимит")
        windows.append(
            window(label, item.get("percent"), item.get("resets_at"), severity=item.get("severity"))
        )
    if not windows:
        for key, label in (("five_hour", "Сессия (5 ч)"), ("seven_day", "Неделя")):
            block = payload.get(key) or {}
            if block.get("utilization") is not None:
                windows.append(window(label, block["utilization"], block.get("resets_at")))

    lines: list[str] = []
    extra = payload.get("extra_usage") or {}
    if extra.get("is_enabled") and extra.get("monthly_limit"):
        lines.append(
            f"Доп. кредиты: {money(float(extra.get('used_credits') or 0))} "
            f"из {money(float(extra['monthly_limit']))}"
        )
    elif extra.get("disabled_reason"):
        lines.append("Доп. кредиты отключены")

    breakdown = (payload.get("seven_day_breakdown") or {}).get("rows") or []
    if breakdown:
        parts = [
            f"{row.get('display_name') or row.get('key')} {float(row.get('percent') or 0):.0f}%"
            for row in breakdown[:4]
        ]
        lines.append("За неделю: " + " · ".join(parts))

    return card(
        pid,
        name,
        sub,
        balance=None,
        windows=windows,
        lines=lines,
        source="api.anthropic.com/api/oauth/usage",
        links=[{"label": "Настройки", "url": "https://claude.ai/settings/usage"}],
    )


# --------------------------------------------------------------------------- #
#  Cursor — GetCurrentPeriodUsage по токену из state.vscdb
# --------------------------------------------------------------------------- #


def _cursor_token() -> str:
    token = sqlite_value(CURSOR_DB, "cursorAuth/accessToken")
    if not token:
        raise SecretMissing(
            "Нет токена Cursor (state.vscdb → cursorAuth/accessToken). Открой Cursor и войди в аккаунт."
        )
    return token


def fetch_cursor() -> dict:
    pid, name, sub = "cursor", "Cursor", "Anysphere · подписка"
    try:
        token = _cursor_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Connect-Protocol-Version": "1",
        }
        usage = _http_json(CURSOR_USAGE_URL, headers=headers, method="POST", body={})
        try:
            profile = _http_json(CURSOR_PROFILE_URL, headers=headers)
        except Exception:  # noqa: BLE001
            profile = {}
    except SecretMissing as exc:
        return unconfigured(pid, name, sub, str(exc))
    except Exception as exc:  # noqa: BLE001
        return card(pid, name, sub, "error", source="api2.cursor.sh", error=_short(exc))

    plan_usage = usage.get("planUsage") or {}
    windows = [
        window("Включённый лимит", plan_usage.get("totalPercentUsed")),
        window("API-модели", plan_usage.get("apiPercentUsed")),
        window("Auto-модели", plan_usage.get("autoPercentUsed")),
    ]

    cycle_start = iso_from_epoch(usage.get("billingCycleStart"))
    cycle_end = iso_from_epoch(usage.get("billingCycleEnd"))

    def cents(key: str) -> float:
        try:
            return float(plan_usage.get(key) or 0) / 100.0
        except (TypeError, ValueError):
            return 0.0

    lines = []
    if plan_usage:
        lines.append(
            f"Потрачено {money(cents('totalSpend'))} · включено {money(cents('includedSpend'))}"
            f" · бонус {money(cents('bonusSpend'))}"
        )
    if cycle_start and cycle_end:
        lines.append(
            "Цикл: "
            + datetime.fromisoformat(cycle_start).strftime("%d.%m")
            + " – "
            + datetime.fromisoformat(cycle_end).strftime("%d.%m")
        )
    spend_limit = usage.get("spendLimitUsage") or {}
    if spend_limit.get("individualLimit"):
        lines.append(
            f"Лимит докупки: использовано {money(float(spend_limit.get('individualUsed') or 0) / 100)}"
            f" из {money(float(spend_limit.get('individualLimit') or 0) / 100)}"
        )

    membership = profile.get("membershipType") or profile.get("individualMembershipType")
    return card(
        pid,
        name,
        sub,
        plan=str(membership).capitalize() if membership else None,
        windows=windows,
        lines=lines,
        source="api2.cursor.sh GetCurrentPeriodUsage",
        links=[{"label": "Аккаунт", "url": "https://cursor.com/settings"}],
    )


# --------------------------------------------------------------------------- #
#  OpenRouter — баланс кредитов и расход ключа
# --------------------------------------------------------------------------- #


def _openrouter_key(secrets: dict[str, str]) -> str:
    token = (
        secrets.get("OPENROUTER_API_KEY")
        or first_env(
            ["OPENROUTER_API_KEY"],
            [
                os.path.join(HOME, ".hermes/.env"),
                os.path.join(HOME, ".config/meeting-tools/openrouter.env"),
            ],
        )
    )
    if not token:
        raise SecretMissing("Нет OPENROUTER_API_KEY (secrets.env или ~/.hermes/.env).")
    return token


def fetch_openrouter(secrets: dict[str, str]) -> dict:
    pid, name, sub = "openrouter", "OpenRouter", "агрегатор моделей · предоплата"
    try:
        token = _openrouter_key(secrets)
        headers = {"Authorization": f"Bearer {token}"}
        credits = (_http_json("https://openrouter.ai/api/v1/credits", headers=headers) or {}).get("data") or {}
        try:
            key_data = (_http_json("https://openrouter.ai/api/v1/key", headers=headers) or {}).get("data") or {}
        except Exception:  # noqa: BLE001
            key_data = {}
    except SecretMissing as exc:
        return unconfigured(pid, name, sub, str(exc))
    except Exception as exc:  # noqa: BLE001
        return card(pid, name, sub, "error", source="openrouter.ai/api/v1", error=_short(exc))

    total = float(credits.get("total_credits") or 0)
    usage = float(credits.get("total_usage") or 0)
    balance = max(0.0, total - usage)

    windows = []
    limit = key_data.get("limit")
    remaining = key_data.get("limit_remaining")
    if isinstance(limit, (int, float)) and limit > 0 and isinstance(remaining, (int, float)):
        windows.append(
            window(
                "Квота ключа",
                (limit - remaining) / limit * 100,
                detail=f"осталось {money(remaining)} из {money(limit)}",
            )
        )

    lines = [f"Пополнено {money(total)} · израсходовано {money(usage)}"]
    monthly = key_data.get("usage_monthly")
    if isinstance(monthly, (int, float)):
        lines.append(f"Расход ключа за месяц: {money(float(monthly))}")
    free_models = key_data.get("free_model_daily_requests") or {}
    if free_models.get("limit"):
        lines.append(
            f"Бесплатные модели: {free_models.get('used', 0)} из {free_models['limit']} запросов в день"
        )

    return card(
        pid,
        name,
        sub,
        balance={"amount": round(balance, 2), "currency": "USD"},
        windows=windows,
        lines=lines,
        source="openrouter.ai/api/v1/credits",
        links=[{"label": "Кредиты", "url": "https://openrouter.ai/settings/credits"}],
    )


# --------------------------------------------------------------------------- #
#  ChatGPT / Codex — wham/usage по OAuth-токену Codex CLI
# --------------------------------------------------------------------------- #


def _codex_tokens() -> tuple[str, str | None]:
    auth = read_json_file(os.path.join(HOME, ".codex/auth.json"))
    tokens = auth.get("tokens") or {}
    token = tokens.get("access_token")
    if not token:
        raise SecretMissing("Нет токена Codex (~/.codex/auth.json). Запусти: codex → вход в ChatGPT.")
    return token, tokens.get("account_id")


def fetch_codex() -> dict:
    pid, name, sub = "codex", "ChatGPT / Codex", "OpenAI · подписка"
    try:
        token, account_id = _codex_tokens()
        payload = _http_json(
            "https://chatgpt.com/backend-api/wham/usage",
            headers={
                "Authorization": f"Bearer {token}",
                "chatgpt-account-id": account_id or "",
                "User-Agent": "codex-cli/0.55.0",
            },
        )
    except SecretMissing as exc:
        return unconfigured(pid, name, sub, str(exc))
    except Exception as exc:  # noqa: BLE001
        return card(pid, name, sub, "error", source="chatgpt.com/backend-api", error=_short(exc))

    rate = payload.get("rate_limit") or {}
    labels = {18000: "Сессия (5 ч)", 604800: "Неделя", 2592000: "Месяц"}
    windows = []
    for key in ("primary_window", "secondary_window"):
        block = rate.get(key) or {}
        if block.get("used_percent") is None:
            continue
        secs = block.get("limit_window_seconds")
        windows.append(
            window(
                labels.get(secs, f"Окно {int(secs) // 3600} ч" if secs else "Окно"),
                block["used_percent"],
                block.get("reset_at"),
            )
        )

    lines = []
    credits = payload.get("credits") or {}
    if credits.get("has_credits") or credits.get("overage_limit"):
        lines.append(f"Кредиты: {'есть' if credits.get('has_credits') else 'нет'}")
    if payload.get("email"):
        lines.append(str(payload["email"]))

    return card(
        pid,
        name,
        sub,
        plan=str(payload.get("plan_type") or "").capitalize() or None,
        windows=windows,
        lines=lines,
        source="chatgpt.com/backend-api/wham/usage",
        links=[{"label": "Тариф", "url": "https://chatgpt.com/#pricing"}],
    )


# --------------------------------------------------------------------------- #
#  GitHub Copilot — gh api /copilot_internal/user
# --------------------------------------------------------------------------- #


def fetch_copilot() -> dict:
    pid, name, sub = "copilot", "GitHub Copilot", "GitHub · подписка"
    gh = shutil.which("gh")
    if not gh:
        return unconfigured(pid, name, sub, "CLI gh не установлен — нужен для чтения квоты Copilot.")
    try:
        res = subprocess.run(
            [gh, "api", "/copilot_internal/user"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if res.returncode != 0:
            raise RuntimeError((res.stderr or "gh api вернул ошибку").strip())
        payload = json.loads(res.stdout)
    except Exception as exc:  # noqa: BLE001
        return card(pid, name, sub, "error", source="gh api /copilot_internal/user", error=_short(exc))

    snapshots = payload.get("quota_snapshots") or {}
    windows = []
    lines = []
    for key, label in (
        ("chat", "Chat"),
        ("completions", "Автодополнение"),
        ("premium_interactions", "Premium-запросы"),
    ):
        block = snapshots.get(key) or {}
        if block.get("percent_remaining") is None:
            continue
        if not block.get("has_quota", True):
            lines.append(f"{label}: не входят в тариф")
            continue
        remaining, total = block.get("quota_remaining"), block.get("entitlement") or block.get("quota_remaining")
        detail = None
        if remaining is not None and total:
            detail = f"осталось {remaining:g} из {total:g}"
        windows.append(window(label, 100 - float(block["percent_remaining"]), detail=detail))

    if payload.get("login"):
        lines.append(f"Аккаунт: {payload['login']}")

    plan = payload.get("copilot_plan") or payload.get("access_type_sku")
    if isinstance(plan, str):
        plan = plan.replace("_", " ").strip().capitalize()
    return card(
        pid,
        name,
        sub,
        plan=str(plan),
        windows=windows,
        lines=lines,
        source="gh api /copilot_internal/user",        links=[{"label": "Copilot", "url": "https://github.com/settings/copilot"}],
    )


# --------------------------------------------------------------------------- #
#  OpenCode Zen — /zen/go/v1/usage
# --------------------------------------------------------------------------- #


def _opencode_key(secrets: dict[str, str]) -> str:
    token = secrets.get("OPENCODE_API_KEY")
    if not token:
        auth = read_json_file(os.path.join(HOME, ".local/share/opencode/auth.json"))
        token = ((auth.get("opencode") or {}).get("key") or "").strip()
    if not token:
        raise SecretMissing("Нет ключа OpenCode (~/.local/share/opencode/auth.json).")
    return token


def fetch_opencode(secrets: dict[str, str]) -> dict:
    pid, name, sub = "opencode", "OpenCode Zen", "opencode.ai · подписка"
    try:
        token = _opencode_key(secrets)
        payload = _http_json(
            "https://opencode.ai/zen/go/v1/usage",
            headers={"Authorization": f"Bearer {token}"},
        )
    except SecretMissing as exc:
        return unconfigured(pid, name, sub, str(exc))
    except Exception as exc:  # noqa: BLE001
        return card(
            pid,
            name,
            sub,
            "error",
            source="opencode.ai/zen/go/v1/usage",
            error=_short(exc),
            links=[{"label": "Ключи", "url": "https://opencode.ai/auth"}],
        )

    usage = payload.get("usage") or {}
    windows = []
    for key, label in (("rolling", "Скользящее окно"), ("weekly", "Неделя"), ("monthly", "Месяц")):
        block = usage.get(key) or {}
        if block.get("percent") is not None:
            windows.append(window(label, block["percent"], block.get("resetsAt")))

    return card(
        pid,
        name,
        sub,
        windows=windows,
        source="opencode.ai/zen/go/v1/usage",
        links=[{"label": "Консоль", "url": "https://opencode.ai/auth"}],
    )


# --------------------------------------------------------------------------- #
#  Apify — /v2/users/me + /v2/users/me/usage/monthly
# --------------------------------------------------------------------------- #


def fetch_apify(secrets: dict[str, str]) -> dict:
    pid, name, sub = "apify", "Apify", "скрейпинг · предоплата"
    token = secrets.get("APIFY_TOKEN") or first_env(["APIFY_TOKEN"])
    if not token:
        return unconfigured(
            pid,
            name,
            sub,
            "Нет APIFY_TOKEN — добавь его в secrets.env (console.apify.com → Settings → API tokens).",
        )
    try:
        me = (_http_json(f"https://api.apify.com/v2/users/me?token={token}", timeout=20) or {}).get("data") or {}
        plan = me.get("plan") or {}
        monthly: dict = {}
        try:
            monthly = (_http_json(
                f"https://api.apify.com/v2/users/me/usage/monthly?token={token}", timeout=20
            ) or {}).get("data") or {}
        except Exception:  # noqa: BLE001
            monthly = {}
    except Exception as exc:  # noqa: BLE001
        return card(pid, name, sub, "error", source="api.apify.com", error=_short(exc))

    used = monthly.get("totalUsageCreditsUsdAfterVolumeDiscount")
    limit = plan.get("monthlyUsageCreditsUsd") or plan.get("maxMonthlyUsageUsd")
    balance = None
    windows = []
    lines = []
    if isinstance(used, (int, float)) and isinstance(limit, (int, float)) and limit > 0:
        windows.append(
            window(
                "Месяц",
                float(used) / float(limit) * 100,
                None,
                detail=f"${float(used):.2f} из ${float(limit):.2f}",
            )
        )
        balance = {"amount": round(float(limit) - float(used), 2), "currency": "USD"}
    elif isinstance(used, (int, float)):
        lines.append(f"Расход за месяц: ${float(used):.2f}")

    cycle = monthly.get("usageCycle") or {}
    if cycle.get("startAt") and cycle.get("endAt"):
        try:
            lines.append(
                "Цикл: "
                + str(cycle["startAt"])[:10]
                + " – "
                + str(cycle["endAt"])[:10]
            )
        except Exception:  # noqa: BLE001
            pass
    if me.get("username"):
        lines.append(f"Аккаунт: {me['username']}")

    return card(
        pid,
        name,
        sub,
        plan=(plan.get("name") or plan.get("id") or None),
        balance=balance,
        windows=windows,
        lines=lines,
        source="api.apify.com/v2/users/me",
        links=[{"label": "Billing", "url": "https://console.apify.com/billing"}],
    )


# --------------------------------------------------------------------------- #
#  SpicyAPI — /api/v1/usage (баланс в USD)
# --------------------------------------------------------------------------- #


def _numeric_leaves(payload: Any, prefix: str = "", depth: int = 0) -> list[tuple[str, float]]:
    """Все числовые листья JSON — на случай незнакомой схемы ответа."""
    found: list[tuple[str, float]] = []
    if depth > 4:
        return found
    if isinstance(payload, dict):
        for key, value in payload.items():
            found += _numeric_leaves(value, f"{prefix}.{key}" if prefix else key, depth + 1)
    elif isinstance(payload, list):
        for index, value in enumerate(payload[:5]):
            found += _numeric_leaves(value, f"{prefix}[{index}]", depth + 1)
    elif isinstance(payload, (int, float)) and not isinstance(payload, bool):
        found.append((prefix, float(payload)))
    elif isinstance(payload, str):
        try:
            found.append((prefix, float(payload)))
        except ValueError:
            pass
    return found


def fetch_spicy(secrets: dict[str, str]) -> dict:
    pid, name, sub = "spicy", "SpicyAPI", "image/video/chat API · предоплата"
    token = secrets.get("SPICY_API_KEY") or first_env(["SPICY_API_KEY"])
    if not token:
        return unconfigured(
            pid,
            name,
            sub,
            "Нет SPICY_API_KEY — добавь в secrets.env ключ sk-spicy-… (spicyapi.ai → Console → API keys).",
        )
    try:
        payload = _http_json(
            "https://api.spicyapi.ai/api/v1/usage",
            headers={"Authorization": f"Bearer {token}"},
        )
    except Exception as exc:  # noqa: BLE001
        return card(pid, name, sub, "error", source="api.spicyapi.ai/api/v1/usage", error=_short(exc))

    leaves = _numeric_leaves(payload)
    balance = None
    lines: list[str] = []
    labels = {
        "balance": "Баланс",
        "credit": "Кредиты",
        "credits": "Кредиты",
        "remaining": "Осталось",
        "spent": "Израсходовано",
        "spent_usd": "Израсходовано, $",
        "used": "Использовано",
        "total": "Всего",
    }
    for path, value in leaves:
        key = path.split(".")[-1].split("[")[0].lower()
        if key in ("balance", "credit", "credits", "remaining") and balance is None:
            balance = {"amount": round(value, 2), "currency": "USD"}
        if key in labels:
            lines.append(f"{labels[key]}: ${value:,.2f}" if key.endswith("usd") or key in ("balance", "credit", "credits", "remaining", "spent", "used", "total") else f"{labels[key]}: {value:g}")
    if not lines and leaves:
        lines = [f"{path}: {value:g}" for path, value in leaves[:6]]

    return card(
        pid,
        name,
        sub,
        balance=balance,
        lines=lines,
        source="api.spicyapi.ai/api/v1/usage",
        links=[{"label": "Биллинг", "url": "https://spicyapi.ai/console/billing"}],
    )


# --------------------------------------------------------------------------- #
#  Hermes — статус пула провайдеров агента (Nous / OpenRouter / Copilot)
# --------------------------------------------------------------------------- #


def fetch_hermes() -> dict:
    pid, name, sub = "hermes", "Hermes Agent", "nousresearch · локальный агент"
    auth = read_json_file(os.path.join(HOME, ".hermes/auth.json"))
    if not auth:
        return unconfigured(pid, name, sub, "Нет ~/.hermes/auth.json — Hermes не авторизован.")

    windows: list[dict] = []
    lines: list[str] = []
    errors: list[str] = []

    for provider, info in (auth.get("providers") or {}).items():
        err = (info or {}).get("last_auth_error") or {}
        if err:
            msg = str(err.get("message") or err.get("code") or "ошибка авторизации")
            errors.append(f"{provider}: {msg}")
            lines.append(f"⚠ {provider}: требуется повторный вход ({msg})")
        else:
            lines.append(f"✓ {provider}: авторизован")

    pool = auth.get("credential_pool") or {}
    for provider, entries in pool.items():
        for entry in entries or []:
            state = entry.get("last_status") or "не использовался"
            label = entry.get("label") or provider
            suffix = " (запросов: %s)" % entry.get("request_count", 0)
            if entry.get("failure_reason") == "billing":
                errors.append(f"{provider}: проблема с биллингом")
                lines.append(f"⚠ {provider}: {label} — проблема с биллингом{suffix}")
            else:
                lines.append(f"{provider}: {label} — {state}{suffix}")

    active = auth.get("active_provider")
    status = "error" if errors else "ok"
    return card(
        pid,
        name,
        sub,
        status,
        plan=f"активен: {active}" if active else None,
        windows=windows,
        lines=lines,
        source="~/.hermes/auth.json",
        links=[{"label": "Портал Nous", "url": "https://portal.nousresearch.com/billing"}],
    )


# --------------------------------------------------------------------------- #
#  Кастомные провайдеры из config.json
# --------------------------------------------------------------------------- #


def fetch_custom(spec: dict, secrets: dict[str, str]) -> dict:
    pid = spec.get("id") or "custom"
    name = spec.get("name") or pid
    sub = spec.get("subtitle") or "custom endpoint"
    token = secrets.get(spec.get("token_env", ""), "") if spec.get("token_env") else ""
    if spec.get("token_env") and not token:
        return unconfigured(pid, name, sub, f"Нет {spec['token_env']} в secrets.env.")

    headers = dict(spec.get("headers") or {})
    if token:
        headers["Authorization"] = str(spec.get("auth_header") or "Bearer {token}").format(token=token)
    try:
        payload = _http_json(spec["url"], headers=headers, timeout=20)
    except Exception as exc:  # noqa: BLE001
        return card(pid, name, sub, "error", source=spec["url"], error=_short(exc))

    def dig(path: str) -> Any:
        node: Any = payload
        for part in str(path).split("."):
            if not part:
                continue
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return None
        return node

    balance = None
    if spec.get("balance_path"):
        value = dig(spec["balance_path"])
        try:
            balance = {"amount": round(float(value), 2), "currency": spec.get("currency", "USD")}
        except (TypeError, ValueError):
            balance = None

    windows = []
    for item in spec.get("windows") or []:
        windows.append(
            window(item.get("label", "Лимит"), dig(item.get("percent_path", "")), dig(item.get("reset_path", "")) if item.get("reset_path") else None)
        )

    lines = []
    for item in spec.get("lines") or []:
        value = dig(item.get("path", ""))
        if value is not None:
            lines.append(f"{item.get('label', item.get('path'))}: {value}")

    return card(
        pid,
        name,
        sub,
        plan=spec.get("plan"),
        balance=balance,
        windows=windows,
        lines=lines,
        source=spec["url"],
        links=spec.get("links") or [],
    )


# --------------------------------------------------------------------------- #
#  Точка входа: параллельный сбор всех карточек
# --------------------------------------------------------------------------- #

BUILTIN = {
    "claude": lambda secrets: fetch_claude(),
    "cursor": lambda secrets: fetch_cursor(),
    "openrouter": fetch_openrouter,
    "codex": lambda secrets: fetch_codex(),
    "copilot": lambda secrets: fetch_copilot(),
    "opencode": fetch_opencode,
    "apify": fetch_apify,
    "spicy": fetch_spicy,
    "hermes": lambda secrets: fetch_hermes(),
}

ORDER = ["claude", "cursor", "openrouter", "codex", "copilot", "opencode", "apify", "spicy", "hermes"]


def collect(config: dict, secrets: dict[str, str]) -> dict:
    """Собирает карточки всех включённых провайдеров параллельно."""
    enabled = config.get("providers") or {}
    jobs: list[tuple[str, Any]] = []
    for pid in ORDER:
        settings = enabled.get(pid) or {}
        if settings.get("enabled") is False:
            continue
        if pid in BUILTIN:
            jobs.append((pid, BUILTIN[pid]))

    custom_specs = [spec for spec in (config.get("custom") or []) if spec.get("enabled", True)]

    cards: list[dict] = []
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(fn, secrets): pid for pid, fn in jobs}
        for spec in custom_specs:
            futures[pool.submit(fetch_custom, spec, secrets)] = spec.get("id", "custom")
        for future, pid in futures.items():
            try:
                result = future.result(timeout=45)
            except Exception as exc:  # noqa: BLE001
                result = card(pid, pid, "", "error", error=_short(exc))
            if isinstance(result, tuple):
                result = result[0]
            cards.append(result)

    rank = {pid: index for index, pid in enumerate(ORDER)}
    cards.sort(key=lambda item: rank.get(item.get("id", ""), 99))
    problems = sum(1 for item in cards if item.get("status") in ("error", "warn"))
    return {
        "generated_at": now_iso(),
        "problems": problems,
        "cards": cards,
    }
