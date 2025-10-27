"""
AES-256 file encryption / decryption with integrity verification (Encrypt-then-MAC).
"""

import os
import time
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
from os import urandom
from utils import derive_key, sha256_hex, save_metadata, load_metadata

BACKEND = default_backend()

def encrypt_file(src_path: str, password: str, out_path: str = None):
    """Encrypt a file and save as .enc with metadata."""
    if not out_path:
        out_path = src_path + '.enc'

    salt = urandom(16)
    iv = urandom(16)
    key = derive_key(password, salt)

    with open(src_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

    hm = hmac.HMAC(key, hashes.SHA256(), backend=BACKEND)
    hm.update(salt + iv + ct)
    mac = hm.finalize()

    with open(out_path, 'wb') as out:
        out.write(b'SFST')        # magic header
        out.write(salt)
        out.write(iv)
        out.write(mac)
        out.write(ct)

    meta = load_metadata()
    meta_entry = {
        'file': os.path.basename(out_path),
        'original': os.path.basename(src_path),
        'sha256': sha256_hex(src_path),
        'timestamp': int(time.time())
    }
    meta[os.path.basename(out_path)] = meta_entry
    save_metadata(meta)

    return out_path

def decrypt_file(enc_path: str, password: str, out_path: str = None):
    """Decrypt a .enc file and verify integrity."""
    if not out_path:
        if enc_path.endswith('.enc'):
            out_path = enc_path[:-4]
        else:
            out_path = enc_path + '.dec'

    with open(enc_path, 'rb') as f:
        magic = f.read(4)
        if magic != b'SFST':
            raise ValueError("Not a valid encrypted file.")
        salt = f.read(16)
        iv = f.read(16)
        mac = f.read(32)
        ct = f.read()

    key = derive_key(password, salt)

    hm = hmac.HMAC(key, hashes.SHA256(), backend=BACKEND)
    hm.update(salt + iv + ct)
    hm.verify(mac)  # raises InvalidSignature if tampered

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    padded = cipher.decryptor().update(ct) + cipher.decryptor().finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()

    with open(out_path, 'wb') as f:
        f.write(data)
    return out_path
