# Secure File Storage System (AES-256) 🔐

A simple, secure Python tool for local file encryption/decryption using AES-256 with integrity verification.

---

## 🚀 Features
- AES-256-CBC encryption with PKCS7 padding  
- PBKDF2-HMAC-SHA256 key derivation  
- HMAC-SHA256 for tamper detection  
- Metadata logging (file name, SHA-256, timestamp)  

---

## 🧰 Tools Used
- Python 3.8+  
- cryptography library  

---

## ⚙️ Installation
```bash
git clone https://github.com/yourusername/secure-file-storage.git
cd secure-file-storage
pip install -r requirements.txt
