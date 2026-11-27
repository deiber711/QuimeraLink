$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$cache = if ($env:PLAYWRIGHT_BROWSERS_PATH) { $env:PLAYWRIGHT_BROWSERS_PATH } else { Join-Path $env:LOCALAPPDATA 'ms-playwright' }
$revision = python -c "import json, pathlib, playwright; browsers=json.loads((pathlib.Path(playwright.__file__).parent/'driver/package/browsers.json').read_text())['browsers']; print(next(b['revision'] for b in browsers if b['name']=='chromium-headless-shell'))"
$chromium = Join-Path $cache "chromium_headless_shell-$revision"
if (!(Test-Path $chromium)) { throw 'Instala Chromium con python -m playwright install chromium.' }
python -m PyInstaller --noconfirm --clean --onefile --windowed --name QuimeraLink --add-data "$chromium;chromium" --add-data 'datos_dominios;datos_dominios' main.py
exit $LASTEXITCODE
