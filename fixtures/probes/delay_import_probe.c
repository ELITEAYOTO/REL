/* Static-only PE32+ delayed-import probe; produced by MSVC on Windows CI.
 * REL must NEVER execute, load, or redistribute the generated DLL/EXE.
 * Neither this source nor its generated binaries carry established redistribution rights.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* The actual DLL and import library are built from existing tracked source.
 * /DELAYLOAD:rel-delay-target.dll routes this imported function via the
 * linker-supplied delay-load descriptor and helper (delayimp.lib).
 */
__declspec(dllimport) DWORD rel_dll_probe_transform(DWORD value);

int main(void)
{
    return (int)(rel_dll_probe_transform(11u) & 0x7fu);
}
