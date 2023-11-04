$pwd = $MyInvocation.MyCommand.Path
Start-Transcript -Append "$pwd/../../logs/log.txt"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    Write-Output "Script not being run with Admin Privileges. Stopping."
    exit
}

$StartTime = Get-Date
Write-Output "Running Win Script on $StartTime`n"

& $pwd/../../recon.ps1

$installTools = Read-Host "Install tools? May take a while: [y/n] (Default: n)"
if($installTools -eq "n"){
    & $pwd/../../install-tools.ps1
}

& $pwd/../../enable-firewall.ps1
& $pwd/../../enable-defender.ps1

$SecurePassword = ConvertTo-SecureString -String 'CyberPatriot123!@#' -AsPlainText -Force
$ad = Read-Host "Does this computer have AD? [y/n] (Default: y/n)"

& $pwd/../../local-users.ps1 -Password $SecurePassword
if($ad -eq "Y"){
    & $pwd/../../ad-users.ps1 -Password $SecurePassword
}

& $/import-gpo.ps1
& $pwd/../../import-secpol.ps1
& $pwd/../../auditpol.ps1
& $pwd/../../uac.ps1
<#
add check for if gpo break -> prob try/catch?
if gpo AND secpol breaks, run uac.ps1, auditpol.ps1
#>

& $pwd/../../services.ps1

& $pwd/../../remove-nondefaultshares.ps1 
cmd /c (bcdedit /set {current} nx AlwaysOn)

$firefox = Read-Host "Is Firefox on this system? [y/n] (Default: n)"
if($firefox -eq "n"){
    & $pwd/../../configure-firefox.ps1
}

# view hidden files
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
taskkill /f /im explorer.exe
Start-Sleep 2
Start-Process explorer.exe

$EndTime = Get-Date
$ts = New-TimeSpan -Start $StartTime -End $EndTime
Write-output "Elapsed Time (HH:MM:SS): $ts`n"
Stop-Transcript
Add-Content -Path "$pwd/../../logs/logs.txt" "Script finished at $EndTime"
Invoke-Item "$pwd/../../logs/log.txt"