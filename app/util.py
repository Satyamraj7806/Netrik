from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

FMT = "%Y-%m-%d %H:%M:%S"


def now() -> str:
    return datetime.now(timezone.utc).strftime(FMT)


def shift(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(FMT)


def parse(ts):
    return datetime.strptime(ts, FMT).replace(tzinfo=timezone.utc) if ts else None


def hours_since(ts) -> float:
    p = parse(ts)
    return 1e9 if p is None else (datetime.now(timezone.utc) - p).total_seconds() / 3600


def ago(ts) -> str:
    if not ts:
        return "never"
    s = int(hours_since(ts) * 3600)
    if s < 60:
        return "just now"
    if s < 3600:
        return f"{s // 60} min ago"
    if s < 86400:
        return f"{s // 3600} h ago"
    return f"{s // 86400} d ago"


def local(ts) -> str:
    p = parse(ts)
    return p.astimezone().strftime("%d %b %Y %H:%M") if p else "-"


def norm_mac(m):
    if not m:
        return None
    digits = re.sub(r"[^0-9a-f]", "", str(m).lower())
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)) if len(digits) == 12 else None


def is_random_mac(m) -> bool:
    return bool(m) and bool(int(m[:2], 16) & 2)


def jl(s, default=None):
    try:
        return json.loads(s) if s else (default if default is not None else {})
    except (TypeError, ValueError):
        return default if default is not None else {}
