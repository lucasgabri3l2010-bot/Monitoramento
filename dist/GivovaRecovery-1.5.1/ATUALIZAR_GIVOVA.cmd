@echo off
setlocal EnableExtensions
set "RECOVERY_PS1=%~dp0Recover-Givova.ps1"
set "RECOVERY_ARGS="
if /I "%~1"=="startup" set "RECOVERY_ARGS= -StartupOnly"

if not exist "%RECOVERY_PS1%" (
  echo Recover-Givova.ps1 nao foi encontrado ao lado deste arquivo.
  pause
  exit /b 1
)

if /I "%~1"=="startup" (echo Givova Monitor - reparo da inicializacao automatica) else (echo Givova Monitor - recuperacao para 1.5.1)
echo Confirme a janela de Administrador (UAC) para continuar.
rem The script path is quoted so pendrive folders with spaces also work.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File \"' + $env:RECOVERY_PS1 + '\"' + $env:RECOVERY_ARGS); exit $p.ExitCode"
set "RESULT=%ERRORLEVEL%"

echo.
if "%RESULT%"=="0" (
  if /I "%~1"=="startup" (echo Tarefa de inicializacao reparada; instalacao preservada.) else (echo Recuperacao concluida: Givova Monitor 1.5.1 ativo e report confirmado.)
  pause
  exit /b 0
)
if "%RESULT%"=="2" (
  echo Givova Monitor 1.5.1 instalado e em execucao, mas o primeiro report nao foi confirmado.
  echo Verifique a rede. Detalhes em C:\ProgramData\GivovaMonitor\logs\recovery-1.5.1.log
  pause
  exit /b 2
)
echo A recuperacao nao foi concluida. Consulte C:\ProgramData\GivovaMonitor\logs\recovery-1.5.1.log
pause
exit /b %RESULT%
