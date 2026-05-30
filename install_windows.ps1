# NetAsset Collector – Windows Setup
# Als Administrator ausführen: .\install_windows.ps1

$ErrorActionPreference = "Stop"
$InstallDir = "C:\ProgramData\NetAsset\Collector"
$ConfDir    = "C:\ProgramData\NetAsset"
$LogFile    = "C:\ProgramData\NetAsset\collector.log"

Write-Host "==> NetAsset Collector – Windows Setup" -ForegroundColor Cyan

# 1. osquery installieren
if (-not (Get-Command osqueryi.exe -ErrorAction SilentlyContinue)) {
    Write-Host "==> Installiere osquery..." -ForegroundColor Yellow

    # Winget versuchen (Windows 10/11)
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install osquery.osquery --silent --accept-package-agreements --accept-source-agreements
    } else {
        # Direktdownload MSI
        $msiUrl = "https://pkg.osquery.io/windows/osquery-5.13.1.msi"
        $msiPath = "$env:TEMP\osquery.msi"
        Write-Host "    Lade osquery herunter..."
        Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
        Start-Process msiexec.exe -Wait -ArgumentList "/i $msiPath /quiet /norestart"
        Remove-Item $msiPath
    }

    # PATH aktualisieren
    $env:PATH += ";C:\Program Files\osquery"
    Write-Host "    osquery installiert"
} else {
    Write-Host "    osquery bereits vorhanden"
}

# 2. Python prüfen
if (-not (Get-Command python.exe -ErrorAction SilentlyContinue)) {
    Write-Host "==> Installiere Python..." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install Python.Python.3.12 --silent --accept-package-agreements
    } else {
        Write-Host "HINWEIS: Python nicht gefunden. Bitte manuell installieren: https://python.org"
    }
}

# 3. Collector-Dateien kopieren
Write-Host "==> Installiere Collector nach $InstallDir..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfDir | Out-Null

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item "$ScriptDir\netasset_collector.py" "$InstallDir\" -Force

# 4. Konfiguration
$ConfFile = "$ConfDir\collector.conf"
if (-not (Test-Path $ConfFile)) {
    Copy-Item "$ScriptDir\netasset_collector.conf.example" $ConfFile -Force
    Write-Host ""
    Write-Host "  WICHTIG: Konfiguration anpassen:" -ForegroundColor Yellow
    Write-Host "  notepad $ConfFile"
    Write-Host "  -> api_key eintragen (aus NetAsset -> Einstellungen -> API Keys)"
    Write-Host ""
}

# 5. Geplanten Task anlegen (stündlich)
Write-Host "==> Richte geplanten Task ein..."
$Action  = New-ScheduledTaskAction `
    -Execute "python.exe" `
    -Argument "$InstallDir\netasset_collector.py >> $LogFile 2>&1" `
    -WorkingDirectory $InstallDir

$Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -Once -At (Get-Date)
$Settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -StartWhenAvailable

Register-ScheduledTask `
    -TaskName "NetAsset Collector" `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -RunLevel Highest `
    -Force | Out-Null

Write-Host ""
Write-Host "==> Installation abgeschlossen!" -ForegroundColor Green
Write-Host ""
Write-Host "Nächste Schritte:"
Write-Host "  1. notepad $ConfFile  (api_key eintragen)"
Write-Host "  2. Testlauf: python $InstallDir\netasset_collector.py --dry-run"
Write-Host "  3. Erster Upload: python $InstallDir\netasset_collector.py"
Write-Host "  4. Danach läuft der Task stündlich automatisch"
Write-Host ""
Write-Host "Logs: Get-Content $LogFile -Tail 20"
