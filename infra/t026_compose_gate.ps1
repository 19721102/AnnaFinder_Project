param(
    [int]$ComposeWaitSeconds = 240,
    [int]$HttpWaitSeconds = 60,
    [int]$Tail = 200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Set-Location 'C:\AnnaFinder_Project'

$composePath = 'compose.yaml'
if (-not (Test-Path $composePath)) {
    Write-Output '{"blocked":true,"reason":"compose.yaml missing","needed_from_user":["Add compose.yaml"]}'
    exit 1
}

try {
    docker compose -f $composePath config | Out-Null
} catch {
    Write-Output '{"blocked":true,"reason":"docker compose config failed","needed_from_user":["Fix compose.yaml syntax"]}'
    exit 1
}

$helpText = (docker compose up --help | Out-String)
$waitSupported = ($helpText -match '(\s|^)--wait(\s|$)')
Write-Output ("compose_wait_supported:" + $waitSupported.ToString().ToLowerInvariant())
if (-not $waitSupported) {
    Write-Output '{"blocked":true,"reason":"docker compose lacks --wait","needed_from_user":["Install docker compose with --wait support"]}'
    exit 1
}

try {
    docker compose -f $composePath build -q
    docker compose -f $composePath up -d --wait --wait-timeout $ComposeWaitSeconds
    docker compose -f $composePath ps

    $deadline = (Get-Date).AddSeconds($HttpWaitSeconds)
    $backendOk = $false
    $frontendOk = $false
    $progressAt = Get-Date
    while ((Get-Date) -lt $deadline) {
        try {
            $backend = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/healthz' -TimeoutSec 5 -UseBasicParsing
            $backendOk = ($backend.StatusCode -eq 200)
        } catch {
            $backendOk = $false
        }

        try {
            $frontend = Invoke-WebRequest -Uri 'http://127.0.0.1:3000/en/' -TimeoutSec 5 -UseBasicParsing
            $frontendOk = ($frontend.StatusCode -eq 200)
        } catch {
            $frontendOk = $false
        }

        if ($backendOk -and $frontendOk) {
            break
        }
        if ((Get-Date) -ge $progressAt.AddSeconds(10)) {
            Write-Output ("progress: backendOk=" + $backendOk + " frontendOk=" + $frontendOk)
            $progressAt = Get-Date
        }
        Start-Sleep -Seconds 2
    }

    if (-not $backendOk -or -not $frontendOk) {
        throw "Gate failed (backend=$backendOk frontend=$frontendOk)."
    }
} catch {
    $gateFailed = $true
    Write-Output ("compose_gate_failed:" + $_.Exception.Message)
    docker compose -f $composePath ps
    docker compose -f $composePath logs --no-color --tail $Tail
    exit 1
} finally {
    docker compose -f $composePath down -v
}
