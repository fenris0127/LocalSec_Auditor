from __future__ import annotations

import re


MASK = "[REDACTED_SECRET]"

_SECRET_PATTERNS = [
    re.compile(r"sk_(?:test|live)_[A-Za-z0-9_=-]+"),
    re.compile(r"ghp_[A-Za-z0-9_]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r'("Secret"\s*:\s*")[^"]+(")', re.IGNORECASE),
]


def mask_secret_text(value: object) -> str:
    text = "" if value is None else str(value)
    for pattern in _SECRET_PATTERNS:
        if pattern.pattern.startswith('("Secret"'):
            text = pattern.sub(rf"\1{MASK}\2", text)
        else:
            text = pattern.sub(MASK, text)
    return text
