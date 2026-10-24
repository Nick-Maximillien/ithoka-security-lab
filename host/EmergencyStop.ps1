[CmdletBinding()]
param(
    [ValidateSet('StopLab', 'ShutdownWsl')]
    [string]$Action = 'StopLab',
    [string]$Distribution,
    [ValidateSet('WindowsDocker', 'WslDocker')]
    [string]$ExecutionMode,
    [string]$DockerContext,
    [string]$Project,
    [string]$LogPath = "$PSScriptRoot\emergency-stop.log"
)

$ErrorActionPreference = 'Stop'
if ($Action -eq 'StopLab' -and $Project -notmatch '^[a-z0-9][a-z0-9-]{0,62}$') { throw 'Unsafe project identifier.' }
if ($Action -eq 'StopLab' -and ([string]::IsNullOrWhiteSpace($ExecutionMode) -or [string]::IsNullOrWhiteSpace($DockerContext) -or [string]::IsNullOrWhiteSpace($Project))) { throw 'StopLab requires the verified ExecutionMode, DockerContext, and Compose project.' }
if ($ExecutionMode -eq 'WslDocker' -and [string]::IsNullOrWhiteSpace($Distribution)) { throw 'WslDocker requires the verified WSL distribution name.' }
if ($Action -eq 'ShutdownWsl' -and [string]::IsNullOrWhiteSpace($Distribution)) { throw 'ShutdownWsl requires an explicitly confirmed distribution name.' }
if ($Action -eq 'ShutdownWsl') {
    Write-Warning 'This terminates the selected WSL distribution and may stop unrelated workloads.'
    $confirmation = Read-Host "Type SHUTDOWN $Distribution to continue"
    if ($confirmation -cne "SHUTDOWN $Distribution") { throw 'Confirmation mismatch; no action taken.' }
}

function Write-Event([string]$Message) {
    $line = "$(Get-Date -Format o) action=$Action project=$Project $Message"
    Add-Content -LiteralPath $LogPath -Value $line
    Write-Output $line
}

function Invoke-LabDocker([string[]]$Arguments) {
    if ($ExecutionMode -eq 'WslDocker') {
        & wsl.exe -d $Distribution -- docker --context $DockerContext @Arguments
    } else {
        & docker --context $DockerContext @Arguments
    }
}

if ($Action -eq 'StopLab') {
    if ($ExecutionMode -eq 'WslDocker') {
        & wsl.exe -d $Distribution -- docker --context $DockerContext version --format '{{.Server.Version}}' *> $null
    } else {
        & docker --context $DockerContext version --format '{{.Server.Version}}' *> $null
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Docker context validation failed for '$DockerContext' in execution mode '$ExecutionMode'."
        exit 2
    }
    Write-Event "context=$DockerContext starting targeted compose stop"
    Invoke-LabDocker @('compose', '--project-name', $Project, 'stop')
    if ($LASTEXITCODE -ne 0) { Write-Event 'result=fail compose stop'; exit 1 }
    $running = Invoke-LabDocker @('ps', '-q', '--filter', "label=com.docker.compose.project=$Project")
    if ($LASTEXITCODE -ne 0) { Write-Event 'result=unknown container verification failed'; exit 2 }
    if ($running) { Write-Event "result=fail running_owned_containers=$running"; exit 1 }
    Write-Event 'result=pass lab containers are not running'
    exit 0
}

Write-Event "context=$DockerContext terminating explicitly selected distribution=$Distribution"
& wsl.exe --terminate $Distribution
if ($LASTEXITCODE -ne 0) { Write-Event 'result=fail WSL termination failed'; exit 1 }
Write-Event 'result=completed WSL termination; unrelated workloads may have been affected'