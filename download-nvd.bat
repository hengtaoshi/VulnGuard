@echo off
set JAVA_OPTS=-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=7890 -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=7890
set DC_HOME=%~dp0tools\dependency-check
echo [%date% %time%] Starting dependency-check NVD database download...
"%DC_HOME%\bin\dependency-check.bat" --scan "%~dp0dc-init-target" --format JSON --out "%~dp0.dc-report" --project "VulnGuard Init" --nvdApiKey 8c0e67ee-a5dd-4e10-b589-995164a8bf30
echo [%date% %time%] Download complete!
