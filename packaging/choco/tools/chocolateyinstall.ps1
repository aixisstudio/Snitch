# Snitch — chocolatey install script
# EN: The package payload is the repo snapshot; the install delegates to
#     the same GPO silent-installer so behaviour is identical everywhere.
# FR: Le payload est le snapshot du dépôt ; l'install délègue au même
#     installeur silencieux GPO — comportement identique partout.
$ErrorActionPreference = 'Stop'
$tools = Split-Path -Parent $MyInvocation.MyCommand.Definition
$src   = Split-Path -Parent $tools                        # EN: package root / FR: racine du paquet
& powershell -ExecutionPolicy Bypass -File `
    (Join-Path $src 'deploy\gpo\Install-Snitch.ps1') -Source $src
