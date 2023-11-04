Write-Output "`n---Configuring Services"
$pwd = $MyInvocation.MyCommand.Path

$KeepRDP = "N"
$KeepFTP = "N"
$KeepSMB = "N"
$KeepRDP = Read-Host "Is RDP a critical service? [Y/N] (Default: N)"
$KeepFTP = Read-Host "Is FTP a critical service? [Y/N] (Default: N)"
$KeepSMB = Read-Host "Is SMB a critical service? [Y/N] (Default: N)"

if($KeepRDP -eq "Y"){
    Write-Output "Keeping RDP"
    "TermService" | Write-Output -FilePath "$pwd/../../enabled_services.txt"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
}else{
    Write-Output "Disabling RDP"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1
}
if($KeepFTP -eq "Y"){
    Write-Output "Keeping FTP"
    "ftpsvc" | Write-Output -FilePath "$pwd/../../enabled_services.txt"
}else{
    Write-Output "Disabling FTP"
}
if($KeepSMB -eq "Y"){
    Write-Output "Keeping SMB"
    "Server" | Write-Output -FilePath "$pwd/../../enabled_services.txt"
}else{
    Write-Output "Disabling SMB"
}

$EnabledServices = Get-Content -Path "$pwd/../../enabled_services.txt"
$DisabledServices = Get-Content -Path "$pwd/../../disabled_services.txt"

foreach($Service in $EnabledServices) {
    Write-Output "Starting $Service"
    Set-Service $Service -StartupType Automatic
    Start-Service $Service
}
foreach($Service in $DisabledServices) {
    Write-Output "Stopping $Service"
    Set-Service $Service -StartupType Disabled
    Stop-Service $Service
}

<#
probably should write a few try-catches for these for the following cases:
- service not found
- not given permission
#>
