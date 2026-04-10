#!/usr/bin/env python3
"""
CYBR448 Final Project - AES Data-at-Rest Encryption Tool
Author: [Your Name]
"""

import os
import sys
import argparse
import getpass
import struct
import hashlib
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

# ── Constants ────────────────────────────────────────────────────────────────
MAGIC       = b"AES_ENC\x00"   # 8-byte file signature
VERSION     = 1
SALT_SIZE   = 32               # bytes  (PBKDF2 salt)
IV_SIZE     = 16               # bytes  (AES-CBC IV)
PBKDF2_ITER = 600_000          # NIST-recommended minimum (2023)

# ── Key derivation ────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes, key_bits: int) -> bytes:
    """Derive an AES key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_bits // 8,
        salt=salt,
        iterations=PBKDF2_ITER,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def random_key(key_bits: int) -> bytes:
    """Generate a cryptographically random AES key."""
    return secrets.token_bytes(key_bits // 8)


def key_from_hex(hex_str: str, key_bits: int) -> bytes:
    """Parse a user-supplied hex key; raise ValueError on bad input."""
    try:
        key = bytes.fromhex(hex_str.strip())
    except ValueError:
        raise ValueError("Key is not valid hexadecimal.")
    expected = key_bits // 8
    if len(key) != expected:
        raise ValueError(f"Key must be {key_bits} bits ({expected} bytes); got {len(key)*8} bits.")
    return key

# ── File format ───────────────────────────────────────────────────────────────
#
#  Offset  Size  Field
#  ------  ----  -----
#       0     8  MAGIC
#       8     1  version
#       9     1  key_bits  (0x80=128, 0xC0=192, 0x00=256 encoded as bits//8-16)
#      10     1  key_mode  (0 = raw key, 1 = password/PBKDF2)
#      11     1  <reserved>
#      12     4  plaintext_size  (uint32 LE) for padding removal
#      16    32  salt  (zeros when key_mode == 0)
#      48    16  IV
#      64     ?  ciphertext
#
HEADER_FMT      = "<8sBBBBI"   # magic, version, key_size_byte, key_mode, rsvd, plaintext_size
HEADER_BASE_LEN = struct.calcsize(HEADER_FMT)   # 16 bytes


def _pack_header(key_bits: int, key_mode: int, plaintext_size: int) -> bytes:
    # Store key_bits//8 (16, 24, or 32) to fit in a single unsigned byte
    return struct.pack(HEADER_FMT, MAGIC, VERSION, key_bits // 8, key_mode, 0, plaintext_size)


def _unpack_header(data: bytes):
    if len(data) < HEADER_BASE_LEN:
        raise ValueError("File too short to contain a valid header.")
    magic, version, key_bytes, key_mode, _, plaintext_size = struct.unpack(HEADER_FMT, data[:HEADER_BASE_LEN])
    if magic != MAGIC:
        raise ValueError("File does not appear to be encrypted by this tool (bad magic bytes).")
    if version != VERSION:
        raise ValueError(f"Unsupported file version: {version}.")
    key_bits = key_bytes * 8  # convert back to bits
    return key_bits, key_mode, plaintext_size

# ── Core encrypt / decrypt ────────────────────────────────────────────────────

def encrypt_bytes(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Return (iv, ciphertext) using AES-CBC with PKCS7 padding."""
    iv = secrets.token_bytes(IV_SIZE)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    return iv, ciphertext


def decrypt_bytes(ciphertext: bytes, key: bytes, iv: bytes, plaintext_size: int) -> bytes:
    """Return plaintext; raises ValueError on bad key/corrupt data."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except Exception:
        raise ValueError("Decryption failed – wrong key/password or corrupted file.")
    return plaintext[:plaintext_size]

# ── File-level encrypt / decrypt ──────────────────────────────────────────────

def encrypt_file(src: Path, dst: Path, key: bytes, key_bits: int,
                 salt: bytes | None, key_mode: int) -> None:
    plaintext = src.read_bytes()
    iv, ciphertext = encrypt_bytes(plaintext, key)

    salt_bytes = salt if salt is not None else bytes(SALT_SIZE)
    header = _pack_header(key_bits, key_mode, len(plaintext))

    dst.write_bytes(header + salt_bytes + iv + ciphertext)
    print(f"  Encrypted: {src}  →  {dst}")


def decrypt_file(src: Path, dst: Path, password: str | None, raw_key: bytes | None) -> None:
    data = src.read_bytes()

    key_bits, key_mode, plaintext_size = _unpack_header(data)
    offset = HEADER_BASE_LEN
    salt       = data[offset: offset + SALT_SIZE]; offset += SALT_SIZE
    iv         = data[offset: offset + IV_SIZE];   offset += IV_SIZE
    ciphertext = data[offset:]

    if key_mode == 1:      # password-derived key
        if password is None:
            password = getpass.getpass(f"  Password for {src.name}: ")
        key = derive_key(password, salt, key_bits)
    else:                  # raw key supplied
        if raw_key is None:
            hex_str = input(f"  Enter {key_bits}-bit key (hex) for {src.name}: ")
            raw_key = key_from_hex(hex_str, key_bits)
        key = raw_key

    plaintext = decrypt_bytes(ciphertext, key, iv, plaintext_size)
    dst.write_bytes(plaintext)
    print(f"  Decrypted: {src}  →  {dst}")

# ── Path resolution helpers ───────────────────────────────────────────────────

def collect_files(paths: list[str]) -> list[Path]:
    """Expand paths; directories are walked recursively."""
    files = []
    for p in paths:
        path = Path(p)
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file():
                    files.append(f)
        else:
            print(f"  Warning: '{p}' not found, skipping.", file=sys.stderr)
    return files


def enc_output_path(src: Path, out_dir: Path | None) -> Path:
    dst = src.with_suffix(src.suffix + ".enc") if out_dir is None else out_dir / (src.name + ".enc")
    dst.parent.mkdir(parents=True, exist_ok=True)
    return dst


def dec_output_path(src: Path, out_dir: Path | None) -> Path:
    stem = src.stem if src.suffix == ".enc" else src.name + ".dec"
    dst  = src.parent / stem if out_dir is None else out_dir / stem
    dst.parent.mkdir(parents=True, exist_ok=True)
    return dst

# ── Interactive key setup (encrypt) ──────────────────────────────────────────

def setup_encrypt_key(args) -> tuple[bytes, bytes | None, int]:
    """
    Returns (key, salt_or_None, key_mode).
    key_mode 0 = raw key, 1 = password-derived
    """
    key_bits = args.bits

    if args.key_mode == "password":
        password = getpass.getpass("  Password: ")
        confirm  = getpass.getpass("  Confirm password: ")
        if password != confirm:
            sys.exit("  Error: passwords do not match.")
        salt = secrets.token_bytes(SALT_SIZE)
        key  = derive_key(password, salt, key_bits)
        print(f"  Key derived via PBKDF2-HMAC-SHA256 ({PBKDF2_ITER:,} iterations).")
        return key, salt, 1

    # Raw key path
    if args.key_source == "generate":
        key = random_key(key_bits)
        print(f"  Generated {key_bits}-bit key: {key.hex()}")
        print("  *** Save this key – it cannot be recovered! ***")
        return key, None, 0

    # hex provided on command line
    if args.hex_key:
        key = key_from_hex(args.hex_key, key_bits)
    else:
        hex_str = input(f"  Enter {key_bits}-bit key (hex): ")
        key = key_from_hex(hex_str, key_bits)
    return key, None, 0

# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="encrypt.py",
        description="AES Data-at-Rest Encryption Tool  (CYBR448 Final Project)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a file with a password:
  python encrypt.py encrypt report.pdf --key-mode password

  # Encrypt a folder, generate a 256-bit key automatically:
  python encrypt.py encrypt ./docs --bits 256 --key-mode raw --key-source generate

  # Encrypt multiple targets with a user-supplied hex key:
  python encrypt.py encrypt a.txt b.txt ./folder --bits 192 --key-mode raw --hex-key <hex>

  # Decrypt a single file with a password:
  python encrypt.py decrypt report.pdf.enc --key-mode password

  # Decrypt all .enc files in a folder with a raw key:
  python encrypt.py decrypt ./docs --key-mode raw --hex-key <hex>
""",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # ── encrypt sub-command
    enc = sub.add_parser("encrypt", help="Encrypt files/folders")
    enc.add_argument("targets", nargs="+", help="Files or folders to encrypt")
    enc.add_argument("--bits", type=int, choices=[128, 192, 256], default=256,
                     help="AES key size in bits (default: 256)")
    enc.add_argument("--key-mode", choices=["raw", "password"], required=True,
                     help="'raw' = true AES key,  'password' = PBKDF2-derived key")
    enc.add_argument("--key-source", choices=["generate", "provide"], default="generate",
                     help="For --key-mode raw: generate a new key or provide one (default: generate)")
    enc.add_argument("--hex-key",
                     help="Hex-encoded AES key (used with --key-mode raw --key-source provide)")
    enc.add_argument("--out-dir",
                     help="Directory for encrypted output files (default: alongside originals)")
    enc.add_argument("--delete-original", action="store_true",
                     help="Delete the original file(s) after successful encryption")

    # ── decrypt sub-command
    dec = sub.add_parser("decrypt", help="Decrypt files/folders")
    dec.add_argument("targets", nargs="+", help="Encrypted files or folders to decrypt")
    dec.add_argument("--key-mode", choices=["raw", "password"], required=True,
                     help="Must match what was used at encrypt time")
    dec.add_argument("--hex-key",
                     help="Hex-encoded AES key (used with --key-mode raw)")
    dec.add_argument("--out-dir",
                     help="Directory for decrypted output files (default: alongside .enc files)")

    return p


def cmd_encrypt(args) -> None:
    files = collect_files(args.targets)
    if not files:
        sys.exit("  No files found to encrypt.")

    out_dir = Path(args.out_dir) if args.out_dir else None
    key, salt, key_mode = setup_encrypt_key(args)

    print(f"\n  Encrypting {len(files)} file(s) with AES-{args.bits}-CBC …\n")
    for src in files:
        dst = enc_output_path(src, out_dir)
        encrypt_file(src, dst, key, args.bits, salt, key_mode)
        if args.delete_original:
            src.unlink()
            print(f"  Deleted original: {src}")
    print("\n  Done.")


def cmd_decrypt(args) -> None:
    files = collect_files(args.targets)
    if not files:
        sys.exit("  No files found to decrypt.")

    out_dir = Path(args.out_dir) if args.out_dir else None
    password = None
    raw_key  = None

    if args.key_mode == "password":
        password = getpass.getpass("  Password: ")
    elif args.hex_key:
        # We don't know key_bits yet – it's in each file's header.
        # Parse it lazily per file.  Store the hex string and derive per file.
        raw_key_hex = args.hex_key
        raw_key     = None  # resolved per file below
    
    print(f"\n  Decrypting {len(files)} file(s) …\n")
    for src in files:
        if src.suffix != ".enc":
            print(f"  Skipping {src} (not a .enc file)")
            continue
        dst = dec_output_path(src, out_dir)

        # For raw-key mode, resolve key per file so we get correct key_bits.
        file_raw_key = raw_key
        if args.key_mode == "raw" and args.hex_key:
            # Read header to get key_bits for this file
            data = src.read_bytes()
            key_bits, _, _ = _unpack_header(data)
            file_raw_key = key_from_hex(args.hex_key, key_bits)

        decrypt_file(src, dst, password, file_raw_key)
    print("\n  Done.")


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.command == "encrypt":
        cmd_encrypt(args)
    elif args.command == "decrypt":
        cmd_decrypt(args)


if __name__ == "__main__":
    main()
