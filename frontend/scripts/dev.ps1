$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$devScript = Join-Path $repoRoot "scripts\dev.ps1"

& $devScript
