/* Static-only REL corpus input: compiler output is never executed in CI.
 * Pointer initialization forces a base relocation with /DYNAMICBASE /FIXED:NO.
 * Redistribution rights for the generated executable are not established.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#pragma comment(lib, "kernel32.lib")

static const wchar_t label[] = L"REL structured PE relocation source";
__declspec(dllexport) const wchar_t *rel_structured_pointer = label;

__declspec(dllexport) DWORD rel_structured_query(DWORD value)
{
    return value ^ (DWORD)rel_structured_pointer[0] ^ GetTickCount();
}

int main(void)
{
    return (int)(rel_structured_query(3u) & 0x7fu);
}
