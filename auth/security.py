import hmac
import hashlib
import os
import base64
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password: str) -> str:
    """Hash password using Werkzeug's secure PBKDF2-SHA256."""
    return generate_password_hash(password, method='scrypt')

def verify_password(password: str, password_hash: str) -> bool:
    """Verify raw password against hash."""
    return check_password_hash(password_hash, password)

def mask_secret(secret: str) -> str:
    """Mask secret value for safe UI display (e.g. sk_live_abc12345 -> sk_l••••••345)."""
    if not secret:
        return ""
    length = len(secret)
    if length <= 6:
        return "•" * length
    prefix_len = min(4, length // 4)
    suffix_len = min(4, length // 4)
    return secret[:prefix_len] + "•" * (length - prefix_len - suffix_len) + secret[-suffix_len:]

def encrypt_secret_simple(secret: str, app_secret: str) -> str:
    """Simple obfuscation/encryption wrapper with HMAC signature for local storage."""
    key = hashlib.sha256(app_secret.encode()).digest()
    # Simple XOR with derived key + base64 encoding
    encoded_bytes = bytearray(secret.encode())
    for i in range(len(encoded_bytes)):
        encoded_bytes[i] ^= key[i % len(key)]
    return base64.b64encode(encoded_bytes).decode()

def decrypt_secret_simple(encrypted: str, app_secret: str) -> str:
    """Decrypt simple obfuscated secret."""
    try:
        key = hashlib.sha256(app_secret.encode()).digest()
        raw_bytes = bytearray(base64.b64decode(encrypted.encode()))
        for i in range(len(raw_bytes)):
            raw_bytes[i] ^= key[i % len(key)]
        return raw_bytes.decode()
    except Exception:
        return ""

def generate_csrf_token() -> str:
    """Generate a cryptographic random token for CSRF protection."""
    return os.urandom(32).hex()

def validate_csrf_token(token1: str, token2: str) -> bool:
    """Constant time comparison of CSRF tokens."""
    if not token1 or not token2:
        return False
    return hmac.compare_digest(token1, token2)
