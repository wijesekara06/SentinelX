"""
SentinelX - AES-256-GCM Encryption Module
NFR-06: All sensitive data at rest shall be encrypted using AES-256.

Each log line or JSON blob is encrypted with:
  - AES-256-GCM (authenticated encryption — provides both
    confidentiality and tamper detection via auth tag)
  - A fresh random 12-byte IV per write, so identical entries
    produce different ciphertext each time
  - A 256-bit key auto-generated on first run and saved to
    sentinelx.key (excluded from version control)

On-disk format per encrypted item:
    base64( IV[12 bytes] + ciphertext + GCM_tag[16 bytes] )
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinelx.key")
_key = None


def _load_key():
    global _key
    if _key is not None:
        return _key

    # Try environment variable first (for production deployments)
    env_val = os.getenv("SENTINELX_ENCRYPTION_KEY", "")
    if env_val:
        candidate = env_val.encode() if len(env_val) == 32 else None
        if candidate is None:
            try:
                candidate = base64.b64decode(env_val)
            except Exception:
                pass
        if candidate and len(candidate) == 32:
            _key = candidate
            return _key
        print("[Encryption] SENTINELX_ENCRYPTION_KEY is not 32 bytes — falling back to key file.")

    # Fall back to auto-generated key file
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            _key = f.read(32)
    else:
        _key = os.urandom(32)
        with open(_KEY_FILE, "wb") as f:
            f.write(_key)
        print(f"[Encryption] AES-256 key generated → {_KEY_FILE}")
        print("[Encryption] Keep sentinelx.key safe — losing it makes encrypted logs unreadable.")

    return _key


def encrypt(plaintext: str) -> str:
    """
    Encrypt a plaintext string with AES-256-GCM.
    Returns a single base64 string safe to write as one line in a log file.
    """
    key    = _load_key()
    iv     = os.urandom(12)
    aesgcm = AESGCM(key)
    # encrypt() appends the 16-byte GCM auth tag automatically
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(iv + ciphertext).decode("ascii")


def decrypt(token: str) -> str:
    """
    Decrypt a base64 AES-256-GCM token back to plaintext.
    Raises an exception if the data has been tampered with.
    """
    key    = _load_key()
    raw    = base64.b64decode(token)
    iv     = raw[:12]
    body   = raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, body, None).decode("utf-8")
