param(
    [int]$WaitTimeout = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Set-Location 'C:\AnnaFinder_Project'

$composeFile = $null
foreach ($candidate in @('compose.yaml', 'compose.yml', 'docker-compose.yml', 'docker-compose.yaml')) {
    if (Test-Path $candidate) {
        $composeFile = $candidate
        break
    }
}

if (-not $composeFile) {
    throw 'No compose file found.'
}

$failed = $false
try {
    docker compose -f $composeFile up -d --build --wait --wait-timeout $WaitTimeout

    $backend = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/healthz' -TimeoutSec 10 -UseBasicParsing
    if ($backend.StatusCode -lt 200 -or $backend.StatusCode -ge 400) {
        throw "Backend health check failed with status $($backend.StatusCode)."
    }

    $frontend = Invoke-WebRequest -Uri 'http://127.0.0.1:3000/en/' -TimeoutSec 10 -UseBasicParsing
    if ($frontend.StatusCode -lt 200 -or $frontend.StatusCode -ge 400) {
        throw "Frontend health check failed with status $($frontend.StatusCode)."
    }
} catch {
    $failed = $true
    Write-Output "compose_gate_failed:$($_.Exception.Message)"
    docker compose -f $composeFile ps
    docker compose -f $composeFile logs --no-color --tail 200
    throw
} finally {
    docker compose -f $composeFile down -v
}
