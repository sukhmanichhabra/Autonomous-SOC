[CmdletBinding()]
param(
    [int]$StreamlitPort = 8501,
    [string]$StreamlitAddress = "0.0.0.0",
    [switch]$SkipPipUpgrade,
    [switch]$SkipRequirementsInstall,
    [switch]$Foreground
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "[setup] $Message" -ForegroundColor Cyan
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
            docker compose logs --tail=100 postgres redis | Out-Host
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

function Start-RedisWithFallback {
    Write-Step "Starting Redis"

    $output = cmd /c "docker compose up -d redis 2>&1"
    $exitCode = $LASTEXITCODE

    if ($output) {
        $output | Out-Host
    }

    if ($exitCode -eq 0) {
        Wait-ForContainer -ContainerName "soc-redis" -TimeoutSeconds 120
        return
    }

    $combinedOutput = ($output | Out-String)
    if ($combinedOutput -match "port is already allocated" -and $combinedOutput -match "6379") {
        Write-Host "[warning] Redis container could not bind 6379 because the port is already in use." -ForegroundColor Yellow

        $redisReachable = $false
        $previousProgressPreference = $ProgressPreference
        try {
            $ProgressPreference = "SilentlyContinue"
            $redisReachable = Test-NetConnection -ComputerName "localhost" -Port 6379 -InformationLevel Quiet
        }
        catch {
            $redisReachable = $false
        }
        finally {
            $ProgressPreference = $previousProgressPreference
        }

        if ($redisReachable) {
            Write-Step "Detected existing Redis listener on localhost:6379. Continuing with that instance."
            return
        }

        Fail "Port 6379 is occupied, and no reachable Redis service was detected on localhost:6379."
    }

    Fail "Starting Redis failed with exit code $exitCode."
}

function Get-ListeningProcessIds {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

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
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    Write-Step "Ensuring port $Port is available"

    $processIds = @(Get-ListeningProcessIds -Port $Port)
    if (-not $processIds -or $processIds.Count -eq 0) {
        Write-Step "Port $Port is already free"
        return
    }

    foreach ($processId in $processIds) {
        if ($processId -eq $PID) {
            continue
        }

        try {
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
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
        if (-not $remaining -or $remaining.Count -eq 0) {
            Write-Step "Port $Port is now free"
            return
        }
        Start-Sleep -Seconds 1
    }

    Fail "Port $Port is still in use after attempting to stop conflicting processes"
}

function Wait-ForPortBinding {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [int]$TimeoutSeconds = 45
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $listeners = @(Get-ListeningProcessIds -Port $Port)
        if ($listeners.Count -gt 0) {
            return $true
        }
        Start-Sleep -Seconds 1
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

    if (-not (Test-Path ".env")) {
        Write-Step "No .env found. Creating an empty .env file."
        New-Item -Path ".env" -ItemType File | Out-Null
    }

    $pythonCommand = Get-PythonCommand
    if (-not $pythonCommand) {
        Fail "Python was not found. Install Python 3 and retry."
    }

    $pythonExecutable = $pythonCommand[0]
    $pythonPrefixArgs = @()
    if ($pythonCommand.Count -gt 1) {
        $pythonPrefixArgs = $pythonCommand[1..($pythonCommand.Count - 1)]
    }

    $venvPython = Join-Path $scriptRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        $createVenvArgs = @()
        $createVenvArgs += $pythonPrefixArgs
        $createVenvArgs += @("-m", "venv", ".venv")
        Invoke-CheckedCommand -Executable $pythonExecutable -Arguments $createVenvArgs -StepName "Creating virtual environment (.venv)"
    }
    else {
        Write-Step "Using existing virtual environment (.venv)."
    }

    if (-not (Test-Path $venvPython)) {
        Fail "Virtual environment creation failed. Missing $venvPython"
    }

    if (-not $SkipPipUpgrade) {
        Invoke-CheckedCommand -Executable $venvPython -Arguments @("-m", "pip", "install", "--upgrade", "pip") -StepName "Upgrading pip"
    }
    else {
        Write-Step "Skipping pip upgrade."
    }

    if (-not $SkipRequirementsInstall) {
        Invoke-CheckedCommand -Executable $venvPython -Arguments @("-m", "pip", "install", "-r", "my-ai-soc-agent/requirements.txt") -StepName "Installing Python dependencies"
    }
    else {
        Write-Step "Skipping requirements installation."
    }

    Invoke-CheckedCommand -Executable "docker" -Arguments @("compose", "up", "-d", "postgres") -StepName "Starting PostgreSQL"
    Wait-ForContainer -ContainerName "soc-postgres" -TimeoutSeconds 180

    Start-RedisWithFallback

    Invoke-CheckedCommand -Executable $venvPython -Arguments @("my-ai-soc-agent/init_db.py") -StepName "Initializing PostgreSQL schema and pgvector"

    $appUrl = "http://localhost:$StreamlitPort"
    Write-Host ""
    Write-Host "[success] Dependencies are running and database is initialized." -ForegroundColor Green
    Write-Host "[success] Streamlit will be available at $appUrl" -ForegroundColor Green
    Write-Host ""

    Stop-ProcessesOnPort -Port $StreamlitPort

    $streamlitArgs = @(
        "-m", "streamlit", "run", "app.py",
        "--server.port", "$StreamlitPort",
        "--server.address", "$StreamlitAddress"
    )

    if ($Foreground) {
        # Foreground mode keeps logs in this terminal and exits on Ctrl+C.
        Invoke-CheckedCommand -Executable $venvPython -Arguments $streamlitArgs -StepName "Starting Streamlit app"
    }
    else {
        $logDir = Join-Path $scriptRoot "logs"
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory | Out-Null
        }

        $stdoutLog = Join-Path $logDir "streamlit.stdout.log"
        $stderrLog = Join-Path $logDir "streamlit.stderr.log"

        Write-Step "Starting Streamlit app (detached)"
        $startProcessArgs = @{
            FilePath = $venvPython
            ArgumentList = $streamlitArgs
            WorkingDirectory = $scriptRoot
            PassThru = $true
            RedirectStandardOutput = $stdoutLog
            RedirectStandardError = $stderrLog
        }
        $streamlitProcess = Start-Process @startProcessArgs

        if (-not $streamlitProcess) {
            Fail "Failed to start Streamlit process."
        }

        if (-not (Wait-ForPortBinding -Port $StreamlitPort -TimeoutSeconds 45)) {
            if (-not $streamlitProcess.HasExited) {
                Stop-Process -Id $streamlitProcess.Id -Force -ErrorAction SilentlyContinue
            }

            $stderrTail = ""
            if (Test-Path $stderrLog) {
                $stderrTail = (Get-Content -Path $stderrLog -Tail 30 | Out-String)
            }

            Fail "Streamlit failed to bind port $StreamlitPort within timeout. $stderrTail"
        }

        Write-Host "[success] Streamlit started in background (PID $($streamlitProcess.Id))." -ForegroundColor Green
        Write-Host "[success] Open: $appUrl" -ForegroundColor Green
        Write-Host "[info] Logs: $stdoutLog and $stderrLog" -ForegroundColor Gray
    }
}
finally {
    Pop-Location
}
