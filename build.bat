@echo off
setlocal

echo [*] Initializing MSVC x64 Environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo [-] Failed to locate vcvars64.bat.
    exit /b 1
)

if not exist bin mkdir bin

echo [*] Assembling x64 MASM Dispatcher (sysgate_asm.asm)...
ml64 /nologo /c /Fo:bin\sysgate_asm.obj src\sysgate_asm.asm
if errorlevel 1 (
    echo [-] MASM assembly failed.
    exit /b 1
)

echo [*] Compiling C Engine and Verification Harness...
cl /nologo /O2 /W4 /I include src\sysgate.c src\main.c /Fo:bin\ /Fe:bin\SysGate.exe bin\sysgate_asm.obj /link /SUBSYSTEM:CONSOLE
if errorlevel 1 (
    echo [-] Compilation failed.
    exit /b 1
)

echo [✓] Build Successful: bin\SysGate.exe
echo.
echo [*] Executing Verification Test:
bin\SysGate.exe
