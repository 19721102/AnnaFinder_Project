Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Set-Location 'C:\AnnaFinder_Project'

$composePath = 'compose.yaml'
$composePresent = Test-Path $composePath
Write-Output ("compose_present:" + $composePresent.ToString().ToLowerInvariant())

$docsPresent = Test-Path 'docs'
$infraPresent = Test-Path 'infra'
$workflowsPresent = Test-Path '.github/workflows'
Write-Output ("required_paths: docs=" + $docsPresent.ToString().ToLowerInvariant() +
    " infra=" + $infraPresent.ToString().ToLowerInvariant() +
    " workflows=" + $workflowsPresent.ToString().ToLowerInvariant())

docker compose version

if (-not $composePresent -or -not $docsPresent -or -not $infraPresent -or -not $workflowsPresent) {
    Write-Output 'compose_config_ok:false'
    exit 1
}

try {
    docker compose -f $composePath config | Out-Null
    Write-Output 'compose_config_ok:true'
} catch {
    Write-Output 'compose_config_ok:false'
    exit 1
}
