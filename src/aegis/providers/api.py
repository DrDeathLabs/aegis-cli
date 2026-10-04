"""Provider API transport contract with bounded pagination/retry behavior.

This is an Aegis adaptation of Trident's retry-aware provider boundaries. It
does not contact a commercial system by itself; tests and integrations inject
the request callable, so live-provider claims remain explicitly unverified.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from typing import Any


class ProviderRequestError(RuntimeError):
    pass


class RateLimited(ProviderRequestError):
    pass


class PermanentProviderError(ProviderRequestError):
    """A provider response error that must not be retried."""
    pass


def paginate_json(request: Callable[[str | None], dict[str, Any]], *, first_page: str | None = None,
                  items_key: str = "items", next_key: str = "next", max_pages: int = 10_000,
                  retries: int = 3, sleep: Callable[[float], None] = time.sleep) -> Iterator[dict[str, Any]]:
    """Yield records through token pagination with bounded exponential retry."""
    if max_pages < 1 or retries < 0:
        raise ValueError("max_pages must be positive and retries must be non-negative")
    token = first_page
    pages = 0
    seen_tokens: set[str] = set()
    while pages < max_pages:
        pages += 1
        token_key = "<first>" if token is None else str(token)
        if token_key in seen_tokens:
            raise ProviderRequestError(f"pagination repeated token: {token!r}")
        seen_tokens.add(token_key)
        last_error: Exception | None = None
        for attempt in range(retries + 1):
            try:
                payload = request(token)
                break
            except RateLimited as exc:
                last_error = exc
                if attempt >= retries:
                    raise
                sleep(min(30.0, 0.25 * (2 ** attempt)))
            except PermanentProviderError:
                raise
            except ProviderRequestError as exc:
                last_error = exc
                if attempt >= retries:
                    raise
                sleep(min(30.0, 0.25 * (2 ** attempt)))
        else:
            raise last_error or ProviderRequestError("provider request failed")
        if not isinstance(payload, dict):
            raise ProviderRequestError("provider response must be an object")
        items = payload.get(items_key, [])
        if not isinstance(items, list):
            raise ProviderRequestError(f"provider response field {items_key!r} must be an array")
        for item in items:
            if not isinstance(item, dict):
                raise ProviderRequestError("provider item must be an object")
            yield item
        next_token = payload.get(next_key)
        if next_token is not None and str(next_token) == token_key:
            raise ProviderRequestError(f"pagination repeated token: {next_token!r}")
        token = next_token
        if not token:
            return
    raise ProviderRequestError(f"pagination exceeded max_pages={max_pages}")
