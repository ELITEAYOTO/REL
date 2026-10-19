@echo off
setlocal EnableExtensions
rem EX-02 static-only source-controlled A/B corpus. NEVER execute built PE files.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Missing vswhere.exe 1>&2
  exit /b 1
)
set "VS_ROOT="
for /f "delims=" %%I in ('"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set "VS_ROOT=%%I"
if not defined VS_ROOT (
  echo Missing MSVC Build Tools 1>&2
  exit /b 1
)
call "%VS_ROOT%\Common7\Tools\VsDevCmd.bat" -no_logo -arch=amd64 -host_arch=amd64
if errorlevel 1 exit /b 1
where clang-cl.exe >nul 2>nul
if errorlevel 1 (
  echo Missing clang-cl.exe 1>&2
  exit /b 1
)
rem Optional controlled linker experiment; the default evidence stays unmodified.
set "REL_DIFF_OUT=corpus-pairs"
set "REL_DIFF_LINK_FLAGS=/INCREMENTAL:NO"
if /I "%~1"=="repro" (
  set "REL_DIFF_OUT=corpus-pairs-repro"
  set "REL_DIFF_LINK_FLAGS=/INCREMENTAL:NO /Brepro"
) else if not "%~1"=="" (
  echo Unknown mode; use no argument or repro 1>&2
  exit /b 1
)
if not exist "%REL_DIFF_OUT%" mkdir "%REL_DIFF_OUT%"
cl.exe /? > "%REL_DIFF_OUT%\msvc-version.txt" 2>&1
clang-cl.exe --version > "%REL_DIFF_OUT%\clang-cl-version.txt"
if errorlevel 1 exit /b 1
link.exe /? > "%REL_DIFF_OUT%\linker-version.txt" 2>&1
if not exist "%REL_DIFF_OUT%\linker-version.txt" exit /b 1
for %%V in (1 2 3 4) do (
  cl.exe /nologo /W4 /WX /O2 /MD /DREL_DIFF_VARIANT=%%V /Fe:%REL_DIFF_OUT%\msvc-v%%V.exe fixtures\probes\diff_version_probe.c /link %REL_DIFF_LINK_FLAGS%
  if errorlevel 1 exit /b 1
  clang-cl.exe /nologo /W4 /WX /O2 /MD /DREL_DIFF_VARIANT=%%V /Fe:%REL_DIFF_OUT%\clang-v%%V.exe fixtures\probes\diff_version_probe.c /link %REL_DIFF_LINK_FLAGS%
  if errorlevel 1 exit /b 1
  if not exist %REL_DIFF_OUT%\msvc-v%%V.exe exit /b 1
  if not exist %REL_DIFF_OUT%\clang-v%%V.exe exit /b 1
)
echo Eight controlled x64 PE variants built in %REL_DIFF_OUT%; no PE was executed
exit /b 0
