/* Controlled EX-02 A/B static-only PE corpus source.
 * CI builds variants with MSVC and clang-cl but NEVER executes them.
 * Build provenance must retain compiler, flags, source SHA and artifact SHA.
 * This test does not grant redistribution rights to generated binaries.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#pragma comment(lib, "kernel32.lib")

#ifndef REL_DIFF_VARIANT
#error REL_DIFF_VARIANT must be 1 or 2
#endif

#if REL_DIFF_VARIANT == 1
__declspec(dllexport) DWORD rel_diff_transform(DWORD value)
{
    return value ^ GetTickCount();
}
#elif REL_DIFF_VARIANT == 2
__declspec(dllexport) DWORD rel_diff_transform(DWORD value)
{
    return value ^ (DWORD)GetTickCount64();
}

__declspec(dllexport) DWORD rel_diff_new_api(DWORD value)
{
    return value + 42u;
}
#else
#error Unsupported REL_DIFF_VARIANT
#endif

int main(void)
{
    return (int)(rel_diff_transform(13u) & 0x7fu);
}
