"""API token handling. Tokens are 256-bit random values, so a plain SHA-256 is enough (no slow KDF needed)."""

from __future__ import annotations

import hashlib
import hmac
import secrets

TOKEN_PREFIX = "cnx_"
_LOOKUP_LEN = len(TOKEN_PREFIX) + 8


def new_api_token() -> tuple[str, str, str]:
    """Return (plaintext shown once, lookup key, sha256 hash to store)."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, lookup_key(token), hash_token(token)


def lookup_key(token: str) -> str:
    return token[:_LOOKUP_LEN]


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def verify_token(token: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), expected_hash)
