Start-Transcript -Append ../logs/log.txt
Write-Output "|| Welcome to Win ||`n"

& $PSScriptRoot/recon.ps1 -DisplayLog $true
& $PSScriptRoot/install-tools.ps1

& $PSScriptRoot/enable-firewall.ps1
& $PSScriptRoot/enable-defender.ps1

$SecurePassword = ConvertTo-SecureString -String 'MonkePatriot123!@#' -AsPlainText -Force

# we need to have recon.ps1 tell us if we have an ad server, if so run the ad-users.ps1
& $PSScriptRoot/local-users.ps1 -Password $SecurePassword
& $PSScriptRoot/ad-users.ps1 -Password $SecurePassword

& $PSScriptRoot/import-gpo.ps1
& $PSScriptRoot/import-secpol.ps1
& $PSScriptRoot/auditpol.ps1
& $PSScriptRoot/uac.ps1
<#
add check for if gpo break -> prob try/catch?

if gpo AND secpol breaks, run uac.ps1, auditpol.ps1
#>

& $PSScriptRoot/services.ps1 -keepRD $false # CHANGE THIS IF REMOTE DESKTOP IS A CRITICAL SERVICE

& $PSScriptRoot/remove-nondefaultshares.ps1 
bcdedit /set {current} nx AlwaysOn

Write-Output "|| ccs.ps1 finished ||`n"
Stop-Transcript
Invoke-Item ".../logs/log.txt"
