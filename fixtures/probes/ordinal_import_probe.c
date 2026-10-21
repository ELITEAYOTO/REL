/* REL controlled static PE ordinal import test; generated files are never run.
 * Source and derived outputs have no established redistribution permission.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef REL_ORDINAL_DLL
/* Export via .def as ordinal 42 NONAME, not via __declspec(dllexport). */
DWORD rel_ordinal_probe(DWORD value)
{
    return value + 17u;
}
#else
/* The import library for NONAME / ordinal 42 must encode an ordinal thunk. */
__declspec(dllimport) DWORD rel_ordinal_probe(DWORD value);

int main(void)
{
    return (int)(rel_ordinal_probe(3u) & 0x7fu);
}
#endif
