"""
Command-line interface for Secure File Storage.
Usage:
  python cli.py encrypt <file> --password <pw>
  python cli.py decrypt <file.enc> --password <pw>
  python cli.py metadata
"""

import argparse
from storage import encrypt_file, decrypt_file
from utils import load_metadata

def main():
    ap = argparse.ArgumentParser(description="Secure File Storage (AES-256)")
    sub = ap.add_subparsers(dest='cmd', required=True)

    e = sub.add_parser('encrypt', help='Encrypt a file')
    e.add_argument('file')
    e.add_argument('--password', '-p', required=True)

    d = sub.add_parser('decrypt', help='Decrypt a file')
    d.add_argument('file')
    d.add_argument('--password', '-p', required=True)

    m = sub.add_parser('metadata', help='View saved metadata')

    args = ap.parse_args()

    if args.cmd == 'encrypt':
        out = encrypt_file(args.file, args.password)
        print(f"[+] Encrypted -> {out}")
    elif args.cmd == 'decrypt':
        out = decrypt_file(args.file, args.password)
        print(f"[+] Decrypted -> {out}")
    elif args.cmd == 'metadata':
        meta = load_metadata()
        for k, v in meta.items():
            print(f"{k} : {v}")

if __name__ == "__main__":
    main()
