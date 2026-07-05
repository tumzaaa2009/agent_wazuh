@echo off
setlocal enabledelayedexpansion
REM =============================================================
REM YARA Active Response สำหรับ Windows Agent
REM ติดตั้งที่: C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat
REM =============================================================
set LOGFILE="C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
set YARA_EXE="C:\Program Files\yara\yara64.exe"
set YARA_RULES="C:\Program Files (x86)\ossec-agent\shared\yara_rules.yar"

echo %date% %time% yara.bat: [DEBUG] Script triggered. >> %LOGFILE%

REM รับ path ไฟล์จาก stdin (Wazuh AR format)
set /p INPUT=
echo %date% %time% yara.bat: [DEBUG] Raw Input: %INPUT% >> %LOGFILE%

for /f "tokens=*" %%a in ('echo %INPUT% ^| "C:\Program Files (x86)\ossec-agent\wodles\python3\python.exe" -c "import sys,json; print(json.load(sys.stdin).get('parameters',{}).get('alert',{}).get('syscheck',{}).get('path',''))"') do set FILEPATH=%%a

if "%FILEPATH%"=="" (
    echo %date% %time% yara.bat: [ERROR] No valid file path parsed from input. >> %LOGFILE%
    exit /b 0
)

if not exist "%FILEPATH%" (
    echo %date% %time% yara.bat: [ERROR] File not found on disk path=%FILEPATH% >> %LOGFILE%
    exit /b 0
)

if not exist %YARA_RULES% (
    echo %date% %time% yara.bat: [ERROR] YARA rules not found at %YARA_RULES% >> %LOGFILE%
    exit /b 0
)

echo %date% %time% yara.bat: [INFO] SCAN_START file=%FILEPATH%. Waiting 2s for IO sync... >> %LOGFILE%

REM Fix race condition
timeout /t 2 /nobreak > nul

echo %date% %time% yara.bat: [DEBUG] Executing %YARA_EXE% -r %YARA_RULES% "%FILEPATH%" >> %LOGFILE%

REM ============ YARA Scan ============
set FOUND_MALWARE=0
set YARA_ERROR=0

REM Execute YARA and capture stderr to a temp file to detect syntax errors
%YARA_EXE% -r %YARA_RULES% "%FILEPATH%" >nul 2> "%TEMP%\yara_err.txt"
if %ERRORLEVEL% NEQ 0 (
    set YARA_ERROR=1
    for /f "usebackq tokens=*" %%e in ("%TEMP%\yara_err.txt") do (
        echo %date% %time% yara.bat: [ERROR] YARA scan failed. Result: %%e >> %LOGFILE%
        echo wazuh-yara: ERROR - YARA scan failed. Result: %%e >> %LOGFILE%
    )
)
del /q "%TEMP%\yara_err.txt" 2>nul

if "%YARA_ERROR%"=="0" (
    for /f "tokens=*" %%r in ('%YARA_EXE% -r %YARA_RULES% "%FILEPATH%" 2^>nul') do (
        echo %date% %time% yara.bat: [WARN] MALWARE_DETECTED file=%FILEPATH% result=%%r >> %LOGFILE%
        set FOUND_MALWARE=1

        REM คำนวณ Hash
        echo %date% %time% yara.bat: [DEBUG] Computing hashes... >> %LOGFILE%
        for /f "tokens=1" %%h in ('certutil -hashfile "%FILEPATH%" SHA256 ^| findstr /v "hash"') do set SHA256=%%h
        for /f "tokens=1" %%m in ('certutil -hashfile "%FILEPATH%" MD5 ^| findstr /v "hash"') do set MD5=%%m

        REM ลบไฟล์มัลแวร์
        del /f /q "%FILEPATH%"
        if not exist "%FILEPATH%" (
            echo %date% %time% yara.bat: [DEBUG] File successfully deleted. >> %LOGFILE%
        ) else (
            echo %date% %time% yara.bat: [ERROR] Failed to delete file. >> %LOGFILE%
        )

        REM เขียน Log (Wazuh Decoder parseable)
        echo wazuh-yara: INFO - Scan result: %%r %FILEPATH% >> %LOGFILE%
        echo QUARANTINED src=%FILEPATH% dest=DELETED sha256=!SHA256! md5=!MD5! yara_match=%%r >> %LOGFILE%
    )
)

if "%FOUND_MALWARE%"=="0" (
    echo %date% %time% yara.bat: [INFO] CLEAN file=%FILEPATH% >> %LOGFILE%
)

echo %date% %time% yara.bat: [DEBUG] Script completed. >> %LOGFILE%
exit /b 0
