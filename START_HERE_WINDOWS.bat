@echo off
setlocal
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py -3 -m pip install --user --no-deps "%~dp0" || goto fail
  py -3 -m defentail ui
) else (
  where python >nul 2>nul
  if %ERRORLEVEL% NEQ 0 (
    echo Python 3.10+ is needed. Install from python.org and run this again.
    pause
    exit /b 1
  )
  python -m pip install --user --no-deps "%~dp0" || goto fail
  python -m defentail ui
)
exit /b 0
:fail
echo Installation failed. See the error above. Nothing was uploaded.
pause
exit /b 1
