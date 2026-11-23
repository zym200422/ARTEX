@echo off
rem ARTEX local launcher (Windows, no Docker).
rem  1. start portable PostgreSQL on 127.0.0.1:5433 (data in PGBASE\pgdata)
rem  2. start ARTEX on http://localhost:8789 (traffic proxy 127.0.0.1:8790)
rem Closing this window stops artex; the database keeps running and is reused.
rem NOTE: keep this file ASCII-only - cmd.exe parses .bat as the OEM codepage.
setlocal

set "APP=%~dp0"
set "PGBASE=%USERPROFILE%\artex-local"
set "PGBIN=%PGBASE%\tools\pgsql\bin"
set "PGDATA=%PGBASE%\pgdata"
rem This instance runs its own copy of the binary from APPDIR, NOT from the
rem project folder. ARTEX resolves jwt.key against the executable's directory
rem (config.BaseDir): running the project's artex.exe would share the signing
rem key with the Docker instance, so a token issued by one would be accepted by
rem the other.
set "APPDIR=%PGBASE%\artex-app"
set "ARTEX_DATA=%PGBASE%\artex-data"
rem Pin the config explicitly: config.Path() prefers .\config.json in the CURRENT
rem working directory, and this script cd's into the project folder - without
rem this the local instance would silently read the project's config.json.
set "ARTEX_CONFIG=%APPDIR%\config.json"
rem Skills are read-only definitions, so sharing them is safe and keeps both
rem instances on the same skill set.
set "ARTEX_SKILL_DIR=%APP%skills"

cd /d "%APP%"

if not exist "%APPDIR%\artex.exe" (
	echo [artex] %APPDIR%\artex.exe not found - run build-local.bat first 1>&2
	exit /b 1
)

"%PGBIN%\pg_isready.exe" -h 127.0.0.1 -p 5433 >nul 2>&1
if not errorlevel 1 (
	echo [pg] PostgreSQL already running on 127.0.0.1:5433
	goto pgready
)

echo [pg] starting PostgreSQL on 127.0.0.1:5433 ...
"%PGBIN%\pg_ctl.exe" -D "%PGDATA%" -l "%PGBASE%\pglog\pg.log" -o "-p 5433" start
if errorlevel 1 (
	echo [pg] start failed - see %PGBASE%\pglog\pg.log 1>&2
	exit /b 1
)
set /a tries=0
:waitpg
"%PGBIN%\pg_isready.exe" -h 127.0.0.1 -p 5433 >nul 2>&1
if not errorlevel 1 goto pgready
set /a tries+=1
if %tries% geq 20 (
	echo [pg] not ready after 20s 1>&2
	exit /b 1
)
ping -n 2 127.0.0.1 >nul
goto waitpg

:pgready
echo.
echo [artex] web     ^-^> http://localhost:8789
echo [artex] proxy   ^-^> 127.0.0.1:8790
echo [artex] app     ^-^> %APPDIR%
echo [artex] data    ^-^> %ARTEX_DATA%
echo [artex] closing this window stops artex
echo.
rem -data and APPDIR are what keep this instance isolated from the Docker one.
"%APPDIR%\artex.exe" -addr :8789 -proxy 127.0.0.1:8790 -data "%ARTEX_DATA%"

endlocal
