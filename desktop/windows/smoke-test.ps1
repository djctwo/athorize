# Smoke-test a built Athorize .exe on Windows (used by CI; safe to run by hand).
# Starts the exe against a throwaway data folder, waits for /api/health, checks
# the web UI is served, then either logs in as the demo admin and lists the
# frameworks (-Demo) or confirms the first-run Setup screen is required and
# that its "Explore with demo data" choice loads the bundled demo (blank).
# Always stops the process and deletes the throwaway data folder.
param(
  [Parameter(Mandatory)] [string] $Exe,
  [int] $Port = 8013,
  [switch] $Demo,
  [int] $TimeoutSec = 180
)
$ErrorActionPreference = 'Stop'
$base = "http://127.0.0.1:$Port"
$data = Join-Path ([IO.Path]::GetTempPath()) ("athorize-smoke-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $data | Out-Null
$env:DATA_DIR = $data
$env:PORT = "$Port"
$env:BROWSER = 'none'
Write-Host "Starting $Exe on $base (data: $data)"
$proc = Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden
try {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $healthy = $false
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { throw "The app exited early with code $($proc.ExitCode)" }
    try {
      $h = Invoke-RestMethod "$base/api/health" -TimeoutSec 5
      if ($h.status -eq 'ok') { $healthy = $true; break }
    } catch { Start-Sleep -Seconds 2 }
  }
  if (-not $healthy) { throw "No healthy response from $base/api/health within $TimeoutSec s" }
  Write-Host "Health OK (version $($h.version))"

  $ui = Invoke-WebRequest "$base/" -UseBasicParsing
  if ($ui.Content -notmatch 'id="root"') { throw "The web UI was not served at /" }
  $deep = Invoke-WebRequest "$base/controls" -UseBasicParsing
  if ($deep.Content -notmatch 'id="root"') { throw "Deep link /controls did not return the web UI" }
  Write-Host "UI OK"

  if ($Demo) {
    $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $body = @{ username = 'admin'; password = 'admin' } | ConvertTo-Json
    Invoke-RestMethod "$base/api/auth/login" -Method Post -Body $body -ContentType 'application/json' -WebSession $s | Out-Null
    $fw = Invoke-RestMethod "$base/api/frameworks" -WebSession $s
    if (@($fw).Count -lt 18) { throw "Expected at least 18 frameworks, got $(@($fw).Count)" }
    Write-Host "Demo login OK, $(@($fw).Count) frameworks listed"
  } else {
    $st = Invoke-RestMethod "$base/api/auth/status"
    if (-not $st.setup_token_required) { throw "Blank build should require the first-run setup token" }
    Write-Host "Blank build OK: setup token required"
    # The blank build ships the demo seed too: "Explore with demo data" (with the
    # first-run token) loads it and signs in as the demo admin.
    $token = (Get-Content (Join-Path $data 'setup-token') -Raw).Trim()
    $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $body = @{ setup_token = $token } | ConvertTo-Json
    Invoke-RestMethod "$base/api/auth/setup/demo" -Method Post -Body $body -ContentType 'application/json' -WebSession $s -TimeoutSec 300 | Out-Null
    $fw = Invoke-RestMethod "$base/api/frameworks" -WebSession $s
    if (@($fw).Count -lt 18) { throw "Expected at least 18 frameworks after loading demo data, got $(@($fw).Count)" }
    Write-Host "Blank build OK: demo data loaded from the Setup screen, $(@($fw).Count) frameworks listed"
  }
  Write-Host "SMOKE TEST PASSED"
} finally {
  # A one-file PyInstaller exe is a bootloader plus a child Python process: kill the tree,
  # or the child keeps the port and the data folder (which then cannot be deleted).
  if (-not $proc.HasExited) { & taskkill.exe /PID $proc.Id /T /F | Out-Null }
  Start-Sleep -Seconds 2
  Remove-Item -Recurse -Force $data -ErrorAction SilentlyContinue
}
