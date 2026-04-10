# AES Data-at-Rest Encryption Tool
**CYBR 448 – Cryptography | Spring 2026 | Final Project – Option 1 (Individual)**

A command-line Python tool for encrypting and decrypting files and folders at rest using AES-CBC. Supports 128-, 192-, and 256-bit keys, password-derived keys (PBKDF2), and true random cryptographic keys.

---

## Features

- Encrypt/decrypt a single file, multiple files, a single folder, or multiple folders
- AES-CBC with 128, 192, or 256-bit keys
- **Password mode** – key derived from a password using PBKDF2-HMAC-SHA256
- **Raw key mode** – randomly generated key, or supply your own in hexadecimal
- Self-contained encrypted file format – all metadata needed for decryption is embedded in the file header
- No plaintext key material ever written to disk

---

## Requirements

- Python 3.12+
- [cryptography](https://cryptography.io/) library

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

### General Syntax

```
python encrypt.py <command> <targets> [options]
```

| Command    | Description                        |
|------------|------------------------------------|
| `encrypt`  | Encrypt one or more files/folders  |
| `decrypt`  | Decrypt one or more `.enc` files/folders |

### Options – `encrypt`

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--bits` | `128`, `192`, `256` | `256` | AES key size |
| `--key-mode` | `raw`, `password` | *(required)* | Key type |
| `--key-source` | `generate`, `provide` | `generate` | For `--key-mode raw` only |
| `--hex-key` | hex string | — | Key in hex (with `--key-source provide`) |
| `--out-dir` | path | alongside original | Output directory |
| `--delete-original` | — | off | Delete original file(s) after successful encryption |

### Options – `decrypt`

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--key-mode` | `raw`, `password` | *(required)* | Must match what was used at encrypt time |
| `--hex-key` | hex string | — | Key in hex (for `--key-mode raw`) |
| `--out-dir` | path | alongside `.enc` file | Output directory |

---

## Examples

### Encrypt a single file with a password
```bash
python encrypt.py encrypt report.pdf --key-mode password
```
You will be prompted to enter and confirm a password. Output: `report.pdf.enc`

---

### Decrypt that file
```bash
python encrypt.py decrypt report.pdf.enc --key-mode password
```
You will be prompted for the password. Output: `report.pdf`

---

### Encrypt a folder, auto-generate a 256-bit key
```bash
python encrypt.py encrypt ./documents --bits 256 --key-mode raw --key-source generate
```
The generated key is printed to the terminal in hex — **save it, it cannot be recovered.**

---

### Decrypt that folder with the saved key
```bash
python encrypt.py decrypt ./documents --key-mode raw --hex-key <your-hex-key>
```

---

### Encrypt multiple targets with a 192-bit password-derived key
```bash
python encrypt.py encrypt notes.txt ./photos ./backups --bits 192 --key-mode password
```

---

### Encrypt providing your own hex key
```bash
python encrypt.py encrypt data.csv --bits 128 --key-mode raw --key-source provide --hex-key aabbccddeeff00112233445566778899
```

---

### Encrypt to a specific output directory
```bash
python encrypt.py encrypt ./docs --key-mode password --out-dir ./encrypted_output
```

---

### Encrypt and delete the original file after encryption
```bash
python encrypt.py encrypt report.pdf --key-mode password --delete-original
```
The original `report.pdf` will be permanently deleted after encryption. Use with caution.

---

## Encrypted File Format

Every `.enc` file starts with a structured binary header:

```
Offset  Size  Field
------  ----  -----
0       8     Magic bytes ("AES_ENC\0")
8       1     Version
9       1     Key size in bits (128 / 192 / 256)
10      1     Key mode (0 = raw, 1 = password/PBKDF2)
11      1     Reserved (0x00)
12      4     Original plaintext size (uint32 LE)
16      32    PBKDF2 salt (zeros if key mode = 0)
48      16    AES-CBC Initialization Vector (IV)
64      ?     Ciphertext (PKCS#7 padded)
```

---

## Cryptographic Details

| Parameter | Value |
|-----------|-------|
| Cipher | AES-CBC |
| Block size | 128 bits |
| Supported key sizes | 128, 192, 256 bits |
| Padding | PKCS#7 |
| IV | 128-bit, generated fresh per file via `secrets.token_bytes()` |
| KDF (password mode) | PBKDF2-HMAC-SHA256 |
| KDF salt | 256-bit, generated fresh per encryption |
| KDF iterations | 600,000 (OWASP 2023 recommendation) |
| Randomness source | Python `secrets` module (OS CSPRNG) |
| Library | [PyCA cryptography](https://cryptography.io/) ≥ 42.0.0 |

> **Note:** AES-CBC does not provide authenticated encryption. Ciphertext integrity is not verified. For a production system, AES-GCM or an HMAC layer should be added.

---

## Project Structure

```
.
├── encrypt.py          # Main tool
├── requirements.txt    # Python dependencies
├── design_document.docx  # Design document (project deliverable)
└── README.md           # This file
```

---

## Deliverables

- [x] Design document
- [x] Source code (`encrypt.py`)
- [x] Remote Git repository
- [ ] Recorded video demonstration

---

## References

- NIST FIPS 197 – Advanced Encryption Standard (AES)
- NIST SP 800-132 – Password-Based Key Derivation
- OWASP Password Storage Cheat Sheet (2023)
- [PyCA cryptography documentation](https://cryptography.io/en/latest/)
- RFC 2898 – PKCS #5: Password-Based Cryptography Specification v2.0
