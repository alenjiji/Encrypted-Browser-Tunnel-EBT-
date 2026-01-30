@echo off
REM Phase 4 Threat Model Enforcement
REM Fails CI if Phase 4 invariants are violated

echo === Phase 4 Threat Model Checks ===

echo Checking for TLS payload inspection...
findstr /S /R /C:"tls_payload" /C:"decrypt_payload" /C:"inspect.*tls" /C:"parse.*tls_data" src\*.rs >nul 2>&1
if %errorlevel% equ 0 (
    echo ERROR: TLS payload inspection detected - violates Phase 4 invariants
    exit /b 1
)

echo Checking for HTTP parsing after CONNECT...
findstr /S /C:"CONNECT" src\*.rs | findstr /R /C:"parse.*http" /C:"http.*parse" /C:"HttpRequest" /C:"HttpResponse" | findstr /V "handle_http_request" >nul 2>&1
if %errorlevel% equ 0 (
    echo ERROR: HTTP parsing after CONNECT detected - violates Phase 4 invariants
    exit /b 1
)

echo Checking for destination domain/IP logging...
findstr /S /R /C:"log.*host" /C:"log.*domain" /C:"log.*destination" /C:"println.*host" /C:"println.*domain" src\*.rs | findstr /V "LEAK ANNOTATION" >nul 2>&1
if %errorlevel% equ 0 (
    echo ERROR: Destination identifier logging detected - violates Phase 4 invariants
    exit /b 1
)

echo ✅ All Phase 4 threat model checks passed