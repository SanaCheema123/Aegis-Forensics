param([switch]$Install)
$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectDir
$pythonExe = Join-Path $projectDir '.venv/Scripts/python.exe'
$portableNode = Join-Path $projectDir '.tools/node-v24.21.0-win-x64'
if (Test-Path -LiteralPath $portableNode) { $env:PATH = "$portableNode;$env:PATH" }
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) { throw 'Install Node.js 22.12+ or use the workspace portable Node runtime.' }
if ($Install) {
    & $pythonExe -m pip install -r api/requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'API dependency installation failed.' }
    & npm.cmd --prefix frontend ci
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
}
$apiProcess = Start-Process -FilePath $pythonExe -ArgumentList @('-m','uvicorn','api.main:app','--host','127.0.0.1','--port','8000') -WorkingDirectory $projectDir -WindowStyle Hidden -PassThru
try {
    Write-Host 'Aegis API: http://127.0.0.1:8000/docs'
    Write-Host 'Aegis website: http://127.0.0.1:5173 (Ctrl+C to stop)'
    & npm.cmd --prefix frontend run dev
} finally {
    if (-not $apiProcess.HasExited) { Stop-Process -Id $apiProcess.Id }
}
