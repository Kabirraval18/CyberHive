param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")),
    [int]$IntervalSeconds = 5
)
$envFile = Join-Path $ProjectRoot ".env"
$endpoint = $env:COWRIE_LOG_URL
if (-not $endpoint -and (Test-Path $envFile)) {
    $line = Get-Content $envFile | Where-Object { $_ -match '^COWRIE_LOG_URL=' } | Select-Object -First 1
    if ($line) { $endpoint = $line.Substring(15).Trim() }
}
if (-not $endpoint) { throw "COWRIE_LOG_URL is not configured." }
Set-Location $ProjectRoot
$live = Join-Path $ProjectRoot "data\cowrie_demo\cowrie_live.json"
$tmp = Join-Path $ProjectRoot "data\cowrie_demo\cowrie_live.tmp.json"
New-Item -ItemType Directory -Force (Split-Path $live) | Out-Null
while ($true) {
    try {
        Invoke-WebRequest -Uri $endpoint -OutFile $tmp -ErrorAction Stop
        Move-Item -Force $tmp $live
        python -c "from backend.app import create_app; from backend.parser.cowrie_parser import parse_cowrie_file; from backend.processing.pipeline import process_cowrie_events; app=create_app(); ctx=app.app_context(); ctx.push(); print(process_cowrie_events(parse_cowrie_file('data/cowrie_demo/cowrie_live.json')))"
    } catch { Write-Host "Collector error: $($_.Exception.Message)" }
    Start-Sleep -Seconds $IntervalSeconds
}
