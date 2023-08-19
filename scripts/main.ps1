Start-Transcript -Append ../logs/log.txt
Write-Output "|| Welcome to Win ||`n"

# $PSScriptRoot/fix.ps1
$PSScriptRoot/install-tools.ps1

$PSScriptRoot/enable-firewall.ps1
$PSScriptRoot/enable-defender.ps1

$SecurePassword = ConvertTo-SecureString -String 'CyberPatriot123!@#' -AsPlainText -Force
$PSScriptRoot/configure-local-users.ps1 -Password $SecurePassword
$PSScriptRoot/configure-ad-users.ps1 -Password $SecurePassword

$PSScriptRoot/import-gpo.ps1
$PSScriptRoot/import-secpol.ps1 # if secpol breaks, run uac.ps1, auditpol.ps1

$PSScriptRoot/configure-services.ps1 -keepRD $false

$PSScriptRoot/remove-nondefaultshares.ps1 
bcdedit /set {current} nx AlwaysOn

Write-Output "|| ccs.ps1 finished ||`n"
Stop-Transcript
Invoke-Item ".../logs/log.txt"