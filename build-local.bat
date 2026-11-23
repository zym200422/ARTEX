@echo off
rem Rebuild artex.exe. ASCII-only - see start-local.bat.
rem   build-local.bat      rebuild the Go binary only (frontend already embedded)
rem   build-local.bat ui   rebuild the Next.js export first, then the binary
setlocal

set "APP=%~dp0"
set "GOBASE=%USERPROFILE%\artex-local"
set "PATH=%GOBASE%\tools\go\bin;%PATH%"
set "GOPATH=%GOBASE%\gopath"
set "GOMODCACHE=%GOBASE%\gopath\pkg\mod"
set "GOCACHE=%GOBASE%\gocache"
set "GOPROXY=https://goproxy.cn,direct"
set "GOSUMDB=off"
rem The machine-wide proxy points at a dead port (127.0.0.1:10809); clear it or
rem every download fails with "proxyconnect tcp: connection refused".
set "HTTP_PROXY="
set "HTTPS_PROXY="
set "ALL_PROXY="

cd /d "%APP%"

if /i "%1"=="ui" (
	echo [build] rebuilding frontend static export ...
	pushd web
	set "NEXT_EXPORT=1"
	call npx next build
	if errorlevel 1 (
		popd
		exit /b 1
	)
	popd
	if exist "server\webui\dist" rmdir /s /q "server\webui\dist"
	mkdir "server\webui" 2>nul
	xcopy /e /i /q "web\out" "server\webui\dist" >nul
	echo [build] frontend assets updated
)

echo [build] compiling artex.exe ...
set CGO_ENABLED=0
go build -tags embedui -trimpath -o artex.exe ./cmd/artex
if errorlevel 1 (
	echo [build] build failed 1>&2
	exit /b 1
)

rem The local instance runs its own copy from APPDIR so its jwt.key and data stay
rem separate from the Docker deployment (see start-local.bat).
echo [build] deploying to %GOBASE%\artex-app ...
if not exist "%GOBASE%\artex-app" mkdir "%GOBASE%\artex-app"
copy /y artex.exe "%GOBASE%\artex-app\artex.exe" >nul
if errorlevel 1 (
	echo [build] deploy failed 1>&2
	exit /b 1
)
echo [build] done -^> artex.exe ^(+ %GOBASE%\artex-app\artex.exe^)

endlocal
