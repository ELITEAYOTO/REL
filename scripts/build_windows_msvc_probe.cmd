@echo off
setlocal EnableExtensions
rem Build one controlled PE with the runner's existing MSVC toolchain.
rem The resulting EXE is analyzed as DATA only; it must never be executed.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Missing vswhere.exe 1>&2
  exit /b 1
)
set "VS_ROOT="
for /f "delims=" %%I in ('"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set "VS_ROOT=%%I"
if not defined VS_ROOT (
  echo Missing MSVC x64 Build Tools 1>&2
  exit /b 1
)
call "%VS_ROOT%\Common7\Tools\VsDevCmd.bat" -no_logo -arch=amd64 -host_arch=amd64
if errorlevel 1 exit /b 1
if not exist compiler-probes mkdir compiler-probes
cl.exe /nologo /W4 /WX /O2 /MD /Fe:compiler-probes\rel-msvc-probe.exe fixtures\probes\msvc_probe.c
if errorlevel 1 exit /b 1
if not exist compiler-probes\rel-msvc-probe.exe (
  echo Compiler did not produce probe executable 1>&2
  exit /b 1
)
echo Built controlled MSVC PE x64 probe from tracked C source
rem Compile same source with a genuinely distinct compiler frontend (LLVM clang-cl).
rem Use the already configured MSVC/Windows SDK link environment. Fail if absent.
where clang-cl.exe >nul 2>nul
if errorlevel 1 (
  echo Required LLVM clang-cl.exe not found on PATH 1>&2
  exit /b 1
)
clang-cl.exe --version > compiler-probes\clang-cl-version.txt
if errorlevel 1 exit /b 1
clang-cl.exe /nologo /W4 /WX /O2 /MD /Fe:compiler-probes\rel-clang-cl-probe.exe fixtures\probes\msvc_probe.c
if errorlevel 1 exit /b 1
if not exist compiler-probes\rel-clang-cl-probe.exe (
  echo Clang-cl did not produce probe executable 1>&2
  exit /b 1
)
echo Built controlled Clang-cl PE x64 probe from tracked C source
rem Build two new PE variants with RCDATA and a forced DIR64 relocation.
rem We only statically inspect the produced executables.
where rc.exe >nul 2>nul
if errorlevel 1 (
  echo Windows resource compiler rc.exe not found 1>&2
  exit /b 1
)
rc.exe /nologo /fo compiler-probes\rel-structured.res fixtures\probes\structured_probe.rc
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /O2 /MD /Fe:compiler-probes\rel-msvc-structured.exe fixtures\probes\structured_probe.c compiler-probes\rel-structured.res /link /DYNAMICBASE /FIXED:NO
if errorlevel 1 exit /b 1
clang-cl.exe /nologo /W4 /WX /O2 /MD /Fe:compiler-probes\rel-clang-structured.exe fixtures\probes\structured_probe.c compiler-probes\rel-structured.res /link /DYNAMICBASE /FIXED:NO
if errorlevel 1 exit /b 1
if not exist compiler-probes\rel-msvc-structured.exe exit /b 1
if not exist compiler-probes\rel-clang-structured.exe exit /b 1
echo Built two controlled structured PE probes without execution
rem Build a real PE32+ delay-load descriptor from REL-authored controlled C.
rem Use a separately built DLL/import library; do NOT run or load either input.
if not defined VCToolsVersion exit /b 1
if not defined WindowsSDKVersion exit /b 1
cl.exe /nologo /W4 /WX /O2 /MD /LD /Fe:compiler-probes\rel-delay-target.dll fixtures\probes\x86_dll_probe.c /link /IMPLIB:compiler-probes\rel-delay-target.lib
if errorlevel 1 exit /b 1
if not exist compiler-probes\rel-delay-target.lib exit /b 1
cl.exe /nologo /W4 /WX /O2 /MD /Fe:compiler-probes\rel-delay-consumer.exe fixtures\probes\delay_import_probe.c /link compiler-probes\rel-delay-target.lib delayimp.lib /DELAYLOAD:rel-delay-target.dll
if errorlevel 1 exit /b 1
if not exist compiler-probes\rel-delay-target.dll exit /b 1
if not exist compiler-probes\rel-delay-consumer.exe exit /b 1
>compiler-probes\rel-delay-toolchain.txt echo %VCToolsVersion%
>>compiler-probes\rel-delay-toolchain.txt echo %WindowsSDKVersion%
echo Built controlled MSVC x64 delay-load EXE and DLL for static-only checks
rem Independent ordinal import corpus: DLL export #42 NONAME via .def.
rem The consumer links its generated import library; never run either PE.
cl.exe /nologo /W4 /WX /O2 /MD /LD /DREL_ORDINAL_DLL /Fe:compiler-probes\rel-ordinal-target.dll fixtures\probes\ordinal_import_probe.c /link /DEF:fixtures\probes\ordinal_import_probe.def /IMPLIB:compiler-probes\rel-ordinal-target.lib
if errorlevel 1 exit /b 1
if not exist compiler-probes\rel-ordinal-target.lib exit /b 1
if not exist compiler-probes\rel-ordinal-target.dll exit /b 1
cl.exe /nologo /W4 /WX /O2 /MD /Fe:compiler-probes\rel-ordinal-consumer.exe fixtures\probes\ordinal_import_probe.c /link compiler-probes\rel-ordinal-target.lib
if errorlevel 1 exit /b 1
if not exist compiler-probes\rel-ordinal-consumer.exe exit /b 1
echo Built two controlled x64 ordinal-only PE inputs for static inspection
exit /b 0
