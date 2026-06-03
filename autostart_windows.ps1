# DRUCKER Collector - Windows Autostart via Task Scheduler
#
# Richtet einen geplanten Task ein der:
#   - Beim Systemstart automatisch laeuft
#   - Stuendlich wiederholt
#   - Als SYSTEM-Konto laeuft (kein Login noetig)
#
# Aufruf (als Administrator):
#   powershell -ExecutionPolicy Bypass -File autostart_windows.ps1

$ErrorActionPreference = "Stop"

$InstallDir = "C:\ProgramData\NetAsset\Collector"
$ConfFile   = "C:\ProgramData\NetAsset\netasset_collector.conf"
$LogFile    = "C:\ProgramData\NetAsset\drucker-collector.log"
$TaskName   = "DRUCKER Collector"

Write-Host "==> DRUCKER Collector - Windows Autostart Setup" -ForegroundColor Cyan

# Python prüfen
$Python = (Get-Command python -ErrorAction SilentlyContinue)?.Source
if (-not $Python) {
    $Python = (Get-Command python3 -ErrorAction SilentlyContinue)?.Source
}
if (-not $Python) {
    Write-Host "FEHLER: Python nicht gefunden. Bitte installieren: https://python.org" -ForegroundColor Red
    exit 1
}
Write-Host "    Python: $Python"

# Collector prüfen
$Script = "$InstallDir\netasset_collector.py"
if (-not (Test-Path $Script)) {
    Write-Host "FEHLER: Collector nicht gefunden: $Script" -ForegroundColor Red
    Write-Host "Bitte zuerst install_windows.ps1 ausfuehren"
    exit 1
}

# Config prüfen
if (-not (Test-Path $ConfFile)) {
    Write-Host "FEHLER: Config nicht gefunden: $ConfFile" -ForegroundColor Red
    exit 1
}

# Alten Task entfernen falls vorhanden
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Task-Aktionen
$Action = New-ScheduledTaskAction `
    -Execute $Python `
    -Argument "$Script" `
    -WorkingDirectory $InstallDir

# Trigger: beim Start + stündlich
$TriggerBoot = New-ScheduledTaskTrigger -AtStartup
$TriggerHourly = New-ScheduledTaskTrigger `
    -RepetitionInterval (New-TimeSpan -Hours 1) `
    -Once `
    -At (Get-Date)

# Einstellungen
$Settings = New-ScheduledTaskSettingsSet `
    -RunOnlyIfNetworkAvailable `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 5)

# Log-Umleitung via Wrapper
$WrapperScript = "$InstallDir\run_collector.ps1"
@"
`$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Add-Content '$LogFile' "`$timestamp INFO Collector startet..."
& '$Python' '$Script' 2>&1 | Add-Content '$LogFile'
Add-Content '$LogFile' "`$timestamp INFO Collector beendet."
"@ | Set-Content $WrapperScript

$ActionWrapper = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -NonInteractive -File `"$WrapperScript`"" `
    -WorkingDirectory $InstallDir

# Task registrieren (als SYSTEM-Konto, kein Login noetig)
$Principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $ActionWrapper `
    -Trigger @($TriggerBoot, $TriggerHourly) `
    -Settings $Settings `
    -Principal $Principal `
    -Description "DRUCKER Infrastructure Collector - stündlich + beim Start" `
    -Force | Out-Null

Write-Host ""
Write-Host "==> Autostart eingerichtet!" -ForegroundColor Green
Write-Host ""
Write-Host "Befehle:"
Write-Host "  Jetzt ausfuehren:  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "  Status:            Get-ScheduledTask -TaskName '$TaskName'"
Write-Host "  Deaktivieren:      Disable-ScheduledTask -TaskName '$TaskName'"
Write-Host "  Logs:              Get-Content '$LogFile' -Tail 20"
Write-Host ""

# Direkt starten
$start = Read-Host "Collector jetzt sofort starten? (j/n)"
if ($start -eq 'j' -or $start -eq 'J') {
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Collector gestartet. Logs: Get-Content '$LogFile' -Tail 20"
}
