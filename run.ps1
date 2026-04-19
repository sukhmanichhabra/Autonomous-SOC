[CmdletBinding()]
param(
    [int]$DashboardPort = 8501,
    [switch]$Build,
    [switch]$WithWorkers,
    [switch]$WithPgAdmin,
    [switch]$PrepareVenv,
    [switch]$SkipPipUpgrade
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "[setup] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[warning] $Message" -ForegroundColor Yellow
}

function Fail {
    param([string]$Message)
    Write-Host "[error] $Message" -ForegroundColor Red
    exit 1
}

function Get-PythonCommand {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @("py", "-3")
    }

    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @("python")
    }

    if (Get-Command python3 -ErrorAction SilentlyContinue) {
        return @("python3")
    }

    return $null
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$StepName
    )

    Write-Step $StepName
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "$StepName failed with exit code $LASTEXITCODE."
    }
}

function Ensure-EnvFile {
    if (Test-Path ".env") {
        return
    }

    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Step "Created .env from .env.example"
    }
    else {
        New-Item -Path ".env" -ItemType File | Out-Null
        Write-Step "Created empty .env"
    }
}

function Setup-LocalVenv {
    param([switch]$SkipPipUpgrade)

    $pythonCommand = Get-PythonCommand
    if (-not $pythonCommand) {
        Fail "Python 3 was not found. Install Python 3 to create a local .venv."
    }

    $pythonExecutable = $pythonCommand[0]
    $pythonPrefixArgs = @()
    if ($pythonCommand.Count -gt 1) {
        $pythonPrefixArgs = $pythonCommand[1..($pythonCommand.Count - 1)]
    }

    $venvPython = Join-Path (Get-Location).Path ".venv\Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        $createVenvArgs = @()
        $createVenvArgs += $pythonPrefixArgs
        $createVenvArgs += @("-m", "venv", ".venv")
        Invoke-CheckedCommand -Executable $pythonExecutable -Arguments $createVenvArgs -StepName "Creating local virtual environment (.venv)"
    }
    else {
        Write-Step "Using existing local virtual environment (.venv)"
    }

    if (-not (Test-Path $venvPython)) {
        Fail "Virtual environment creation failed. Missing $venvPython"
    }

    if (-not $SkipPipUpgrade) {
        Invoke-CheckedCommand -Executable $venvPython -Arguments @("-m", "pip", "install", "--upgrade", "pip") -StepName "Upgrading local pip"
    }
    else {
        Write-Step "Skipping local pip upgrade"
    }

    Invoke-CheckedCommand -Executable $venvPython -Arguments @("-m", "pip", "install", "-r", "my-ai-soc-agent/requirements.txt") -StepName "Installing local Python dependencies"
}

function Wait-ForContainer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContainerName,
        [int]$TimeoutSeconds = 180
    )

    $startTime = Get-Date
    while ($true) {
        $status = docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" $ContainerName 2>$null

        if ($status -eq "healthy" -or $status -eq "running") {
            Write-Step "$ContainerName is $status"
            return
        }

        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        if ($elapsed -ge $TimeoutSeconds) {
            docker compose logs --tail=120 | Out-Host
            Fail "Timeout waiting for container '$ContainerName'."
        }

        if ([string]::IsNullOrWhiteSpace($status)) {
            Write-Step "Waiting for $ContainerName to be created..."
        }
        else {
            Write-Step "Waiting for $ContainerName (status: $status)..."
        }

        Start-Sleep -Seconds 2
    }
}

function Stop-DockerContainersOnHostPort {
    param([int]$Port)

    $rows = @(docker ps --format "{{.ID}}|{{.Names}}|{{.Ports}}")
    if ($LASTEXITCODE -ne 0) {
        return
    }

    foreach ($row in $rows) {
        if ([string]::IsNullOrWhiteSpace($row)) {
            continue
        }

        $parts = $row -split "\|", 3
        if ($parts.Count -lt 3) {
            continue
        }

        $containerId = $parts[0]
        $containerName = $parts[1]
        $ports = $parts[2]

        if ($ports -match "(0\.0\.0\.0|\[::\]):$Port->") {
            Write-Step "Stopping container '$containerName' using host port $Port"
            docker stop $containerId | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Fail "Failed to stop container '$containerName' on host port $Port"
            }
        }
    }
}

function Get-ListeningProcessIds {
    param([int]$Port)

    $processIds = @()

    try {
        $connections = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
        if ($connections) {
            $processIds = $connections |
                Select-Object -ExpandProperty OwningProcess -Unique |
                Where-Object { $_ -gt 0 }
        }
    }
    catch {
        $processIds = @()
    }

    return @($processIds)
}

function Stop-ProcessesOnPort {
    param([int]$Port)

    Write-Step "Ensuring host port $Port is available"

    Stop-DockerContainersOnHostPort -Port $Port

    $processIds = @(Get-ListeningProcessIds -Port $Port)
    if ($processIds.Count -eq 0) {
        Write-Step "Port $Port is already free"
        return
    }

    foreach ($processId in $processIds) {
        if ($processId -eq $PID) {
            continue
        }

        try {
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($process -and $process.ProcessName -eq "com.docker.backend") {
                continue
            }

            if ($process) {
                Write-Step "Stopping process $($process.ProcessName) (PID $processId) on port $Port"
            }
            else {
                Write-Step "Stopping PID $processId on port $Port"
            }
            Stop-Process -Id $processId -Force -ErrorAction Stop
        }
        catch {
            Fail "Unable to stop PID $processId on port ${Port}: $($_.Exception.Message)"
        }
    }

    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $remaining = @(Get-ListeningProcessIds -Port $Port)
        if ($remaining.Count -eq 0) {
            Write-Step "Port $Port is now free"
            return
        }
        Start-Sleep -Seconds 1
    }

    Fail "Port $Port is still in use after attempting to stop conflicting processes"
}

function Wait-ForHttpEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [int]$TimeoutSeconds = 90
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 8
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                return $true
            }
        }
        catch {
            # Keep waiting until timeout.
        }

        Start-Sleep -Seconds 2
    }

    return $false
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = (Get-Location).Path
}

Push-Location $scriptRoot
try {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Fail "Docker is not installed or not in PATH."
    }

    docker compose version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail "Docker Compose plugin is required (docker compose)."
    }

    Ensure-EnvFile

    if ($PrepareVenv) {
        Setup-LocalVenv -SkipPipUpgrade:$SkipPipUpgrade
    }

    $env:DASHBOARD_PORT = "$DashboardPort"

    Stop-ProcessesOnPort -Port $DashboardPort

    $upCoreArgs = @("compose", "up", "-d")
    if ($Build) {
        $upCoreArgs += "--build"
    }
    $upCoreArgs += @("postgres", "redis")
    Invoke-CheckedCommand -Executable "docker" -Arguments $upCoreArgs -StepName "Starting PostgreSQL and Redis"

    Wait-ForContainer -ContainerName "soc-postgres" -TimeoutSeconds 180
    Wait-ForContainer -ContainerName "soc-redis" -TimeoutSeconds 120

    $initDbArgs = @("compose", "run", "--rm")
    if ($Build) {
        $initDbArgs += "--build"
    }
    $initDbArgs += "init-db"
    Invoke-CheckedCommand -Executable "docker" -Arguments $initDbArgs -StepName "Initializing PostgreSQL schema and pgvector"

    $dashboardArgs = @("compose", "up", "-d")
    if ($Build) {
        $dashboardArgs += "--build"
    }
    $dashboardArgs += "dashboard"
    Invoke-CheckedCommand -Executable "docker" -Arguments $dashboardArgs -StepName "Starting Streamlit dashboard container"

    Wait-ForContainer -ContainerName "soc-dashboard" -TimeoutSeconds 240

    if ($WithWorkers) {
        $workersArgs = @("compose", "--profile", "workers", "up", "-d")
        if ($Build) {
            $workersArgs += "--build"
        }
        $workersArgs += @("producer", "consumer")
        Invoke-CheckedCommand -Executable "docker" -Arguments $workersArgs -StepName "Starting producer and consumer workers"
    }

    if ($WithPgAdmin) {
        $pgAdminArgs = @("compose", "--profile", "tools", "up", "-d", "pgadmin")
        Invoke-CheckedCommand -Executable "docker" -Arguments $pgAdminArgs -StepName "Starting pgAdmin"
    }

    $appUrl = "http://localhost:$DashboardPort"
    if (-not (Wait-ForHttpEndpoint -Url $appUrl -TimeoutSeconds 90)) {
        Write-Warn "Dashboard container is running but HTTP health check timed out for $appUrl"
    }

    Write-Host ""
    Write-Host "[success] Full SOC stack is running in Docker." -ForegroundColor Green
    Write-Host "[success] Dashboard: $appUrl" -ForegroundColor Green
    Write-Host "[info] Core services: postgres, redis, init-db, dashboard" -ForegroundColor Gray
    if ($WithWorkers) {
        Write-Host "[info] Worker services: producer, consumer" -ForegroundColor Gray
    }
    if ($WithPgAdmin) {
        Write-Host "[info] pgAdmin: http://localhost:5050" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "Useful commands:" -ForegroundColor Gray
    Write-Host "  docker compose logs -f dashboard" -ForegroundColor Gray
    Write-Host "  docker compose --profile workers logs -f producer consumer" -ForegroundColor Gray
    Write-Host "  docker compose down" -ForegroundColor Gray
    Write-Host ""
}
finally {
    Pop-Location
}
