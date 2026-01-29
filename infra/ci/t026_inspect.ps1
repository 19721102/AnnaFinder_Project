Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Set-Location 'C:\AnnaFinder_Project'

foreach ($path in @('compose.yaml', 'compose.yml', 'docs', 'infra', '.github/workflows')) {
    if (Test-Path $path) {
        Write-Output ("exists:" + $path)
    } else {
        Write-Output ("missing:" + $path)
    }
}

docker compose version

if (Test-Path 'compose.yaml') {
    docker compose -f compose.yaml config | Out-Null
    Write-Output 'compose_config_ok:true'
}
