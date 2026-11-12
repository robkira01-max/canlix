"""Password hashing using stdlib scrypt (memory-hard, no extra dependencies).

Parameters follow OWASP 2024 guidance for interactive logins:
  N=16384 (2^14), r=8, p=1 — ~16 MB RAM, ~100 ms on a modern CPU.
"""

from __future__ import annotations

import hashlib
import hmac
import os

_N = 16384  # CPU/memory cost (2^14)
_R = 8  # block size
_P = 1  # parallelisation
_SALT_BYTES = 32
_KEY_LEN = 64
_DUMMY_HASH = "0" * (_SALT_BYTES * 2) + ":" + "0" * (_KEY_LEN * 2)


def hash_password(password: str) -> str:
    """Return a 'salt_hex:key_hex' string suitable for storing in the database."""
    salt = os.urandom(_SALT_BYTES)
    key = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=_KEY_LEN)
    return salt.hex() + ":" + key.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time verification. Returns False on malformed hashes."""
    try:
        salt_hex, key_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(key_hex)
    except (ValueError, AttributeError):
        return False
    actual = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=_KEY_LEN)
    return hmac.compare_digest(actual, expected)


def dummy_verify(password: str) -> None:
    """Run a full scrypt to equalise timing when the email is not found."""
    verify_password(password, _DUMMY_HASH)
