# Created by Anthony Kaiser
# Minimal TOTP utilities (no external deps)
import base64
import hmac
import hashlib
import secrets
import struct
import time


def generate_base32_secret(length: int = 16) -> str:
    """Generate a base32-encoded secret (RFC 3548), padding stripped."""
    return base64.b32encode(secrets.token_bytes(length)).decode("utf-8").rstrip("=")


def _totp_digest(secret: str, for_time: float, step: int = 30) -> bytes:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    counter = int(for_time // step)
    msg = struct.pack(">Q", counter)
    return hmac.new(key, msg, hashlib.sha1).digest()


def generate_totp(secret: str, for_time: float | None = None, step: int = 30, digits: int = 6) -> str:
    """Generate TOTP code for the given secret/time."""
    if for_time is None:
        for_time = time.time()
    digest = _totp_digest(secret, for_time, step)
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff
    return str(code_int % (10 ** digits)).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1, step: int = 30, digits: int = 6) -> bool:
    """Verify a TOTP code allowing +/- window steps for clock skew."""
    if not secret or not code or len(code.strip()) < 6:
        return False
    try:
        code_int = int(code)
    except ValueError:
        return False

    now = time.time()
    for offset in range(-window, window + 1):
        if generate_totp(secret, now + offset * step, step=step, digits=digits) == str(code_int).zfill(digits):
            return True
    return False
