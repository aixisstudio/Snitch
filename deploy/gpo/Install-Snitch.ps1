<#
.SYNOPSIS
    Snitch — silent install for GPO/SCCM deployment / installation
    silencieuse pour déploiement GPO/SCCM.

.DESCRIPTION
    EN: Drops the backend into %ProgramFiles%\Snitch, writes the
        declarative config to %ProgramData%\Snitch\snitch.toml (the
        backend applies it at startup — same Security-as-Code contract
        as Linux), creates the venv + pinned deps, and registers a
        SYSTEM scheduled task running headless on 127.0.0.1.
        Designed for a GPO startup script or Intune/MDM win32 app:
            powershell -ExecutionPolicy Bypass -File Install-Snitch.ps1 `
                -Source \\share\snitch -Token <api-token>
    FR: Dépose le backend dans %ProgramFiles%\Snitch, écrit la config
        déclarative dans %ProgramData%\Snitch\snitch.toml (appliquée au
        démarrage — même contrat Security-as-Code que Linux), crée le
        venv + deps épinglées, et enregistre une tâche planifiée SYSTEM
        headless sur 127.0.0.1. Pour script de démarrage GPO ou app
        win32 Intune/MDM.
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Source,                 # EN: repo checkout or share path / FR: checkout ou partage
    [string]$InstallDir = "$env:ProgramFiles\Snitch",
    [string]$DataDir    = "$env:ProgramData\Snitch",
    [string]$Token      = "",        # EN: fixed API token (recommended) / FR: jeton fixe (recommandé)
    [int]$Port          = 8000
)
$ErrorActionPreference = 'Stop'

# EN: 1) Files / FR: 1) Fichiers
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
Copy-Item -Recurse -Force -Path (Join-Path $Source 'backend') `
    -Destination $InstallDir

# EN: 2) Declarative config — file wins over DB, same as Linux.
# FR: 2) Config déclarative — le fichier prime sur la DB, comme Linux.
@"
ask_enabled = false
kill_switch_enabled = true
"@ | Set-Content -Encoding UTF8 -Path (Join-Path $DataDir 'snitch.toml')

# EN: 3) venv + pinned deps / FR: 3) venv + deps épinglées
$py = (Get-Command python -ErrorAction Stop).Source
& $py -m venv (Join-Path $InstallDir 'env')
& (Join-Path $InstallDir 'env\Scripts\python.exe') -m pip install -r `
    (Join-Path $InstallDir 'backend\requirements.txt') --quiet

# EN: 4) Headless scheduled task at startup (SYSTEM, loopback only).
# FR: 4) Tâche planifiée headless au démarrage (SYSTEM, loopback).
$uvicorn = Join-Path $InstallDir 'env\Scripts\pythonw.exe'
$action = New-ScheduledTaskAction -Execute $uvicorn `
    -Argument "-m uvicorn api.main:app --host 127.0.0.1 --port $Port" `
    -WorkingDirectory (Join-Path $InstallDir 'backend')
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
    -LogonType ServiceAccount -RunLevel Highest
$env = "SNITCH_DATA_DIR=$DataDir;SNITCH_CONFIG=" +
       (Join-Path $DataDir 'snitch.toml')
# EN: The token goes to %ProgramData%\Snitch\api_token.txt ACL'd to
#     SYSTEM+Administrators — NOT into run.cmd: Program Files is
#     world-readable, so a plaintext SNITCH_TOKEN=… line would hand the
#     master API key to any local user. The backend auto-reads the file.
# FR: Le jeton va dans %ProgramData%\Snitch\api_token.txt restreint à
#     SYSTEM+Administrateurs — PAS dans run.cmd : Program Files est
#     lisible par tous, donc une ligne SNITCH_TOKEN=… donnerait la clé
#     API maître à tout utilisateur local. Le backend lit le fichier
#     automatiquement.
if ($Token) {
    $tokPath = Join-Path $DataDir 'api_token.txt'
    Set-Content -Encoding ASCII -NoNewline -Path $tokPath -Value $Token
    $acl = Get-Acl $tokPath
    $acl.SetAccessRuleProtection($true, $false)       # EN: cut inheritance / FR: couper l'héritage
    foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRule($rule) | Out-Null }
    foreach ($id in 'SYSTEM', 'Administrators') {
        $acl.AddAccessRule((New-Object `
            System.Security.AccessControl.FileSystemAccessRule(
                $id, 'FullControl', 'Allow')))
    }
    Set-Acl -Path $tokPath -AclObject $acl
}
Register-ScheduledTask -TaskName 'Snitch' -Action $action `
    -Trigger $trigger -Principal $principal -Force `
    -Description 'Snitch network observability backend (headless)'
Set-ScheduledTask -TaskName 'Snitch' -Settings `
    (New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1))
# EN: env vars for the task — via a launcher cmd file (task env is
#     limited). `set "VAR=value"` quoting keeps & and spaces in paths
#     from being interpreted.
# FR: vars d'env de la tâche — via un cmd lanceur (env de tâche limité).
#     `set "VAR=valeur"` empêche & et espaces d'être interprétés.
@"
@echo off
set "SNITCH_DATA_DIR=$DataDir"
set "SNITCH_CONFIG=$(Join-Path $DataDir 'snitch.toml')"
"$uvicorn" -m uvicorn api.main:app --host 127.0.0.1 --port $Port
"@ | Set-Content -Encoding ASCII -Path (Join-Path $InstallDir 'run.cmd')
$action = New-ScheduledTaskAction -Execute (Join-Path $InstallDir 'run.cmd') `
    -WorkingDirectory (Join-Path $InstallDir 'backend')
Set-ScheduledTask -TaskName 'Snitch' -Action $action | Out-Null
Start-ScheduledTask -TaskName 'Snitch'
Write-Host "Snitch installed — API on http://127.0.0.1:$Port (token auth)"
