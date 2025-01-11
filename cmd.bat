@echo off

setlocal

set "CHROME_FLAGS=--proxy-server="socks5://127.0.0.1:1080" ^
--incognito ^
--no-first-run ^
--no-default-browser-check ^
--no-service-autorun ^
--no-experiments ^
--no-report-upload ^
--metrics-recording-only ^
--disable-background-networking ^
--disable-component-update ^
--disable-sync ^
--disable-google-services ^
--disable-client-side-phishing-detection ^
--disable-default-apps ^
--disable-domain-reliability ^
--disable-breakpad ^
--disable-features=OptimizationHints,Translate,ChromeWhatsNew ^
--user-data-dir=%TEMP%\chrome_temp ^
https://google.com"

if "%OS%"=="Windows_NT" (
  start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" %CHROME_FLAGS%
) else (
  echo This script is intended to run on Windows.
)

endlocal
