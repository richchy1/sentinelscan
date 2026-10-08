"""Neutralise untrusted text (banners, headers) before it is stored or shown."""

import re

EVIDENCE_LIMIT = 500
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]+")


def sanitize(data: bytes | str, limit: int = EVIDENCE_LIMIT) -> str:
    """Decode, replace control characters with spaces, collapse spaces, truncate."""
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    text = _CONTROL.sub(" ", text)
    text = re.sub(r" {2,}", " ", text).strip()
    return text[:limit]
