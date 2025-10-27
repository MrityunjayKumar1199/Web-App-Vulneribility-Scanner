"""
Utility helpers for hashing, key derivation, and metadata management.
"""

import os
import json
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def sha256_hex(path):
    """Return SHA256 hash of a file in hex format."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """Derive a 32-byte AES key from password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def save_metadata(metadata: dict, path='metadata.json'):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)

def load_metadata(path='metadata.json'):
    if not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)
