@echo off
set JAVA_OPTS=%JAVA_OPTS%

rem Parse HTTP proxy for both HTTP and HTTPS Java proxy settings
if "%HTTP_PROXY%" NEQ "" (
  for /f "tokens=1,2 delims=:" %%a in ("%HTTP_PROXY:http://=%") do (
    if "%%b" NEQ "" (
      set JAVA_OPTS=%JAVA_OPTS% -Dhttp.proxyHost=%%a -Dhttp.proxyPort=%%b -Dhttps.proxyHost=%%a -Dhttps.proxyPort=%%b
    )
  )
)

set DC_HOME=%~dp0tools\dependency-check
set DATA_DIR=%~dp0..\.nvd-cache\data
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
echo [%date% %time%] Starting dependency-check NVD database download...
set NVD_KEY=
if "%NVD_API_KEY%" NEQ "" set NVD_KEY=--nvdApiKey %NVD_API_KEY%
"%DC_HOME%\bin\dependency-check.bat" --data "%DATA_DIR%" --scan "%~dp0dc-init-target" --format JSON --out "%~dp0.dc-report" --project "VulnGuard Init" %NVD_KEY%
echo [%date% %time%] Download complete!
