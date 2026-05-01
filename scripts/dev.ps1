$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$backendDir = Join-Path $root "backend"
$frontendDir = Join-Path $root "frontend"

function Resolve-CommandPath {
    param(
        [string[]] $Names,
        [string] $InstallHint
    )

    foreach ($name in $Names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }

    throw $InstallHint
}

$localPythonCandidates = @(
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python310\python.exe")
)

$python = if ($env:LOCALSC_PYTHON) {
    $env:LOCALSC_PYTHON
} else {
    $localPython = $localPythonCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($localPython) {
        $localPython
    } else {
        Resolve-CommandPath -Names @("python", "py") -InstallHint "Python 3.11+ is required to run the backend."
    }
}

$npm = Resolve-CommandPath -Names @("npm.cmd", "npm") -InstallHint "Node.js and npm are required to run the frontend."

if (-not (Test-Path (Join-Path $frontendDir "node_modules"))) {
    throw "Frontend dependencies are missing. Run: cd frontend; npm install"
}

$backendArgs = @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload")
$frontendArgs = @("run", "dev", "--", "--host", "127.0.0.1", "--port", "5173")

Write-Host "Starting LocalSec Auditor..."
Write-Host "Backend:  http://127.0.0.1:8000"
Write-Host "Frontend: http://127.0.0.1:5173"
Write-Host "Press Ctrl+C to stop both servers."

$backend = Start-Process -FilePath $python -ArgumentList $backendArgs -WorkingDirectory $backendDir -NoNewWindow -PassThru
$frontend = Start-Process -FilePath $npm -ArgumentList $frontendArgs -WorkingDirectory $frontendDir -NoNewWindow -PassThru

try {
    while (-not $backend.HasExited -and -not $frontend.HasExited) {
        Start-Sleep -Seconds 1
        $backend.Refresh()
        $frontend.Refresh()
    }

    if ($backend.HasExited) {
        throw "Backend server stopped with exit code $($backend.ExitCode)."
    }

    if ($frontend.HasExited) {
        throw "Frontend server stopped with exit code $($frontend.ExitCode)."
    }
} finally {
    foreach ($process in @($backend, $frontend)) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
        }
    }
}
