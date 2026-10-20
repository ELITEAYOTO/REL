/* Static-only, locally built REL x86 DLL input for testing PE32 imports/exports.
 * This source has NO approved redistribution license. Generated DLLs are not
 * committed, uploaded for distribution, loaded or executed.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#pragma comment(lib, "kernel32.lib")

__declspec(dllexport) DWORD rel_dll_probe_transform(DWORD value)
{
    DWORD tick = (DWORD)(GetTickCount64() & 0xFFu);
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    return (value * 13u) ^ tick ^ (kernel != NULL ? 0x39u : 0u);
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return TRUE;
}
