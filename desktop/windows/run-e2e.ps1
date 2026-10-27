# Run the Playwright end-to-end suite against a BUILT Athorize .exe on Windows
# (used by CI; safe to run by hand from the repo root after `npm ci` in frontend/
# and `npx playwright install chromium`).
#
#   ./desktop/windows/run-e2e.ps1 -Exe desktop/dist/Athorize-Demo.exe -Project demo
#   ./desktop/windows/run-e2e.ps1 -Exe desktop/dist/Athorize.exe      -Project blank
#
# The exe IS the server under test (not uvicorn from source): it is started with a
# throwaway data folder, a fixed port and no browser window, the suite runs against
# it (E2E_BASE_URL, E2E_DATA_DIR = that data folder, where the blank project reads
# the setup token), then the exe and its child process are stopped. The exe's
# console output is kept in -LogDir (uploaded by CI when something fails).
param(
  [Parameter(Mandatory)] [string] $Exe,
  [Parameter(Mandatory)] [ValidateSet('demo', 'blank')] [string] $Project,
  [int] $Port = 8042,
  [string] $DataDir = (Join-Path ([IO.Path]::GetTempPath()) "athorize-e2e-$Project"),
  [string] $LogDir = (Join-Path ([IO.Path]::GetTempPath()) "athorize-e2e-logs"),
  [int] $TimeoutSec = 240
)
$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$exePath = (Resolve-Path $Exe).Path
$base = "http://127.0.0.1:$Port"

# Never point this at a real install: the folder is wiped first.
$real = Join-Path $env:USERPROFILE '.athorize-universal'
if ($DataDir.TrimEnd('\').StartsWith($real, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Refusing to use a real data folder: $DataDir"
}
if (Test-Path $DataDir) { Remove-Item -Recurse -Force $DataDir }
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$outLog = Join-Path $LogDir "exe-$Project.out.log"
$errLog = Join-Path $LogDir "exe-$Project.err.log"

$env:DATA_DIR = $DataDir
$env:ATHORIZE_NO_BROWSER = '1'
$env:PYTHONUNBUFFERED = '1'
Write-Host "Starting $exePath on $base (data: $DataDir, logs: $LogDir)"
$proc = Start-Process -FilePath $exePath -ArgumentList @('--port', "$Port", '--no-browser') `
  -RedirectStandardOutput $outLog -RedirectStandardError $errLog -NoNewWindow -PassThru

function Stop-Exe {
  # A one-file PyInstaller exe is a bootloader plus a child Python process: kill the tree.
  if ($proc -and -not $proc.HasExited) { & taskkill.exe /PID $proc.Id /T /F | Out-Null }
  Start-Sleep -Seconds 2
}

$code = 1
try {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $healthy = $false
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { throw "The exe exited early with code $($proc.ExitCode)" }
    try {
      $h = Invoke-RestMethod "$base/api/health" -TimeoutSec 5
      if ($h.status -eq 'ok') { $healthy = $true; break }
    } catch { Start-Sleep -Seconds 2 }
  }
  if (-not $healthy) { throw "No healthy response from $base/api/health within $TimeoutSec s" }
  Write-Host "Health OK (version $($h.version)) - running the '$Project' Playwright project"

  $env:E2E_BASE_URL = $base
  $env:E2E_DATA_DIR = $DataDir
  Push-Location (Join-Path $repo 'frontend')
  try {
    if ($Project -eq 'demo') { & npm run test:e2e } else { & npm run test:e2e:blank }
    $code = $LASTEXITCODE
  } finally { Pop-Location }
} finally {
  Stop-Exe
  if ($code -ne 0) {
    Write-Host "----- exe stdout (last 150 lines) -----"
    if (Test-Path $outLog) { Get-Content $outLog -Tail 150 }
    Write-Host "----- exe stderr (last 150 lines) -----"
    if (Test-Path $errLog) { Get-Content $errLog -Tail 150 }
  }
}
exit $code
