@echo off
set JAVA_OPTS=%JAVA_OPTS%
if "%HTTP_PROXY%" NEQ "" (
  for /f "tokens=1,2 delims=:" %%a in ("%HTTP_PROXY:http://=%") do (
    if "%%b" NEQ "" set JAVA_OPTS=%JAVA_OPTS% -Dhttp.proxyHost=%%a -Dhttp.proxyPort=%%b
  )
)
if "%HTTPS_PROXY%" NEQ "" (
  for /f "tokens=1,2 delims=:" %%a in ("%HTTPS_PROXY:https://=%") do (
    if "%%b" NEQ "" set JAVA_OPTS=%JAVA_OPTS% -Dhttps.proxyHost=%%a -Dhttps.proxyPort=%%b
  )
)
set DC_HOME=%~dp0tools\dependency-check
echo [%date% %time%] Starting dependency-check NVD database download...
set NVD_KEY=
if "%NVD_API_KEY%" NEQ "" set NVD_KEY=--nvdApiKey %NVD_API_KEY%
"%DC_HOME%\bin\dependency-check.bat" --scan "%~dp0dc-init-target" --format JSON --out "%~dp0.dc-report" --project "VulnGuard Init" %NVD_KEY%
echo [%date% %time%] Download complete!
