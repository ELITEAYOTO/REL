@echo off
setlocal EnableExtensions
rem Windows hosted CI only: compile two x86 PE32 DLLs; NEVER load or run them.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Missing vswhere.exe 1>&2
  exit /b 1
)
set "VS_ROOT="
for /f "delims=" %%I in ('"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set "VS_ROOT=%%I"
if not defined VS_ROOT (
  echo Missing MSVC x86 tools 1>&2
  exit /b 1
)
call "%VS_ROOT%\Common7\Tools\VsDevCmd.bat" -no_logo -arch=x86 -host_arch=amd64
if errorlevel 1 exit /b 1
if /I not "%VSCMD_ARG_TGT_ARCH%"=="x86" (
  echo Expected MSVC x86 target environment 1>&2
  exit /b 1
)
if not exist compiler-probes mkdir compiler-probes
rem Do not use /nologo: the MSVC version appears in the CI job log.
cl.exe /W4 /WX /O2 /MD /LD /Fe:compiler-probes\rel-msvc-x86-probe.dll fixtures\probes\x86_dll_probe.c
if errorlevel 1 exit /b 1
if not exist compiler-probes\rel-msvc-x86-probe.dll exit /b 1
where clang-cl.exe >nul 2>nul
if errorlevel 1 (
  echo Missing LLVM Clang-cl 1>&2
  exit /b 1
)
clang-cl.exe --version >compiler-probes\clang-cl-x86-version.txt
if errorlevel 1 exit /b 1
rem Force i686 target; clang-cl on a 64-bit host may otherwise default to x64.
clang-cl.exe --target=i686-pc-windows-msvc /W4 /WX /O2 /MD /LD /Fe:compiler-probes\rel-clang-x86-probe.dll fixtures\probes\x86_dll_probe.c
if errorlevel 1 exit /b 1
if not exist compiler-probes\rel-clang-x86-probe.dll exit /b 1
echo Two x86 PE32 DLL samples compiled; generated samples must not execute
exit /b 0
