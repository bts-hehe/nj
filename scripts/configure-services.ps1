param($KeepRD)

if($KeepRD){
    "TermService" | Write-Output -FilePath "enabled_services.txt"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
}
$EnabledServices = Get-Content -Path "enabled_services.txt"
$DisabledServices = Get-Content -Path "disabled_services.txt"

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