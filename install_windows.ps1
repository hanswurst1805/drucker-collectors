# NetAsset Collector - Windows Setup
# Run as Administrator: powershell -ExecutionPolicy Bypass -File .\install_windows.ps1

$ErrorActionPreference = "Stop"
$InstallDir = "C:\ProgramData\NetAsset\Collector"
$ConfDir    = "C:\ProgramData\NetAsset"
$LogFile    = "C:\ProgramData\NetAsset\collector.log"

Write-Host "==> NetAsset Collector - Windows Setup" -ForegroundColor Cyan

# 1. Install osquery
if (-not (Get-Command osqueryi.exe -ErrorAction SilentlyContinue)) {
    Write-Host "==> Installing osquery..." -ForegroundColor Yellow

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install osquery.osquery --silent --accept-package-agreements --accept-source-agreements
    } else {
        $msiUrl  = "https://pkg.osquery.io/windows/osquery-5.13.1.msi"
        $msiPath = "$env:TEMP\osquery.msi"
        Write-Host "    Downloading osquery..."
        Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
        Start-Process msiexec.exe -Wait -ArgumentList "/i $msiPath /quiet /norestart"
        Remove-Item $msiPath
    }

    $env:PATH += ";C:\Program Files\osquery"
    Write-Host "    osquery installed"
} else {
    Write-Host "    osquery already installed"
}

# 2. Check Python
if (-not (Get-Command python.exe -ErrorAction SilentlyContinue)) {
    Write-Host "==> Installing Python..." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install Python.Python.3.12 --silent --accept-package-agreements
    } else {
        Write-Host "NOTE: Python not found. Install manually: https://python.org"
    }
}

# 3. Copy collector files
Write-Host "==> Installing collector to $InstallDir ..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfDir    | Out-Null

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item "$ScriptDir\netasset_collector.py" "$InstallDir\" -Force

# 4. Configuration
$ConfFile = "$ConfDir\collector.conf"
if (-not (Test-Path $ConfFile)) {
    Copy-Item "$ScriptDir\netasset_collector.conf.example" $ConfFile -Force
    Write-Host ""
    Write-Host "  IMPORTANT: Edit the config file:" -ForegroundColor Yellow
    Write-Host "  notepad $ConfFile"
    Write-Host "  -> Set api_key (from NetAsset -> Settings -> API Keys)"
    Write-Host ""
}

# 5. Scheduled Task (every hour)
Write-Host "==> Creating scheduled task..."
$Action   = New-ScheduledTaskAction -Execute "python.exe" -Argument "$InstallDir\netasset_collector.py" -WorkingDirectory $InstallDir
$Trigger  = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -Once -At (Get-Date)
$Settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -StartWhenAvailable

Register-ScheduledTask -TaskName "NetAsset Collector" -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest -Force | Out-Null

Write-Host ""
Write-Host "==> Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. notepad $ConfFile  (set api_key)"
Write-Host "  2. Test: python $InstallDir\netasset_collector.py --dry-run"
Write-Host "  3. First run: python $InstallDir\netasset_collector.py"
Write-Host "  4. The scheduled task will run automatically every hour"
Write-Host ""
Write-Host "Logs: Get-Content $LogFile -Tail 20"
