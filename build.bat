@echo off
setlocal
echo ===================================================
echo   Sentinel Guard - Release Build & Publish (.NET 8)
echo ===================================================

where dotnet >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] .NET SDK is not found in PATH.
    echo Please install .NET 8 SDK from: https://dotnet.microsoft.com/download/dotnet/8.0
    pause
    exit /b 1
)

echo Building Release package...
dotnet build -c Release
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo Publishing self-contained single-file binary to publish/...
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Publish failed!
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Binary published successfully in: %~dp0publish\SentinelGuard.exe
echo.
pause
