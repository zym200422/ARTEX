@echo off
rem Stop ARTEX and the local PostgreSQL. ASCII-only - see start-local.bat.
setlocal

set "PGBASE=%USERPROFILE%\artex-local"
set "PGBIN=%PGBASE%\tools\pgsql\bin"

taskkill /F /IM artex.exe >nul 2>&1
if errorlevel 1 (
	echo [artex] not running
) else (
	echo [artex] stopped
)

"%PGBIN%\pg_ctl.exe" -D "%PGBASE%\pgdata" stop -m fast >nul 2>&1
if errorlevel 1 (
	echo [pg] not running
) else (
	echo [pg] stopped
)

endlocal
