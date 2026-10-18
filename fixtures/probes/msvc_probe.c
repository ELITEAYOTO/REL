/* Controlled REL PE parsing sample. This executable is NEVER run by CI.
 * No repository license or redistribution grant is implied.
 * Built locally in Windows CI with MSVC x64, not committed as a binary.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static const wchar_t rel_probe_label[] = L"REL static PE corpus - MSVC x64";

__declspec(dllexport) DWORD rel_probe_transform(DWORD value)
{
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    DWORD tick = (DWORD)(GetTickCount64() & 0xFFu);
    return (value * 17u) ^ tick ^ (kernel != NULL ? 0x5Au : 0u)
           ^ (DWORD)(rel_probe_label[0]);
}

int main(void)
{
    return (int)(rel_probe_transform(7u) & 0x7Fu);
}
