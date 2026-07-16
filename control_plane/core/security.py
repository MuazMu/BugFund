"""Secret-handling utilities for the BugFund control plane.

Used by the auth middleware (API-key verification), the tenant layer, and
anywhere secrets must be logged safely. API keys are stored only as a hash;
the plaintext is returned to the tenant exactly once at creation time.

Design notes:
- Key hashes are SHA-256 (fast, sufficient for high-entropy API keys; we are
  not defending against offline brute-force of low-entropy passwords here —
  keys are 32 random bytes). Comparison is constant-time regardless.
- ``mask`` keeps a short prefix/suffix so logs can identify a key without
  exposing it.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

__all__ = [
    "API_KEY_PREFIX",
    "generate_api_key",
    "generate_token",
    "hash_secret",
    "constant_time_verify",
    "mask",
]

API_KEY_PREFIX = "bf_live_"


def generate_api_key() -> str:
    """Generate a new plaintext API key (returned to the tenant once).

    Format: ``bf_live_<43 url-safe base64 chars>`` (32 bytes of entropy).
    Store :func:`hash_secret` of this, never the plaintext.
    """
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"


def generate_token(nbytes: int = 32) -> str:
    """Return a generic url-safe random token (nonce, state, etc.)."""
    return secrets.token_urlsafe(nbytes)


def hash_secret(secret: str) -> str:
    """Return the SHA-256 hex digest of ``secret`` (for storage/lookup)."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def constant_time_verify(provided: str, stored_hash: str) -> bool:
    """True iff ``hash_secret(provided) == stored_hash`` (constant-time)."""
    provided_hash = hash_secret(provided)
    return hmac.compare_digest(provided_hash, stored_hash)


def mask(secret: str, *, keep: int = 4) -> str:
    """Render a secret safe for logs: ``bf_live_1234…WXYZ``.

    Args:
        secret: The secret to mask.
        keep: Characters of prefix/suffix to retain (on top of any key prefix).
    """
    if not secret:
        return "<empty>"
    if len(secret) <= keep * 2:
        return "*" * len(secret)
    return f"{secret[:keep]}…{secret[-keep:]}"
