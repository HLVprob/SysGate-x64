Set-Location -Path $PSScriptRoot

$vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community"
$vcvars = "$vsPath\VC\Auxiliary\Build\vcvars64.bat"

if (!(Test-Path $vcvars)) {
    Write-Error "vcvars64.bat not found at $vcvars"
    exit 1
}

$cmd = @"
call "$vcvars" >nul
if not exist bin mkdir bin
ml64 /c /Fo bin\sysgate_asm.obj src\sysgate_asm.asm
cl /nologo /O2 /W4 /I include src\sysgate.c src\main.c /Fo:bin\ /Fe:bin\SysGate.exe bin\sysgate_asm.obj /link /SUBSYSTEM:CONSOLE
bin\SysGate.exe
"@

Set-Content -Path "run_build.bat" -Value $cmd -Encoding ASCII
cmd.exe /c run_build.bat
Remove-Item -Path "run_build.bat" -Force
