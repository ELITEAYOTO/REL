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
exit /b 0
