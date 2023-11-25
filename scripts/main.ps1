Start-Transcript -Append "$PSScriptRoot/../logs/log.txt"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    Write-Output "Script not being run with Admin Privileges. Stopping."
    exit
}
if(($PSVersionTable.PSVersion | Select-object -expandproperty Major) -lt 3){ # check Powershell version > 3+
    Write-Output "The Powershell version does not support PSScriptRoot. Stopping." 
    exit
}
$Internet = $true
if($null -eq (Get-NetRoute | Where-Object DestinationPrefix -eq '0.0.0.0/0' | Get-NetIPInterface | Where-Object ConnectionState -eq 'Connected')){
    Write-Output "The computer has no Internet. Adjusting script to compensate."
    $Internet = $false
}
$StartTime = Get-Date
Write-Output "Running Win Script on $StartTime`n"

$productType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType # 1=workstation, 2=DC, 3=Server(not DC) 

& $PSScriptRoot/recon.ps1
if($Internet){
    $installTools = Read-Host "Install tools? May take a while: [y/n] (Default: n)"
    if(($installTools -eq "y") -or ($installTools -eq "Y")){
        & $PSScriptRoot/install-tools.ps1
    }
}

# & $PSScriptRoot/service-enum.ps1 -productType $productType
& $PSScriptRoot/services.ps1 -productType $productType

& $PSScriptRoot/enable-firewall.ps1
& $PSScriptRoot/enable-defender.ps1

& $PSScriptRoot/import-secpol.ps1
& $PSScriptRoot/auditpol.ps1
& $PSScriptRoot/uac.ps1
<#
add check for if gpo break -> prob try/catch?
if gpo AND secpol breaks, run uac.ps1, auditpol.ps1
#>

$SecurePassword = ConvertTo-SecureString -String 'CyberPatriot123!@#' -AsPlainText -Force

if(![String]::IsNullOrWhiteSpace((Get-Content -Path "$PSScriptRoot/../users.txt")) -and ![String]::IsNullOrWhiteSpace((Get-Content -Path "$PSScriptRoot/../admins.txt"))){
    if($productType -eq "2"){
        & $PSScriptRoot/ad-users.ps1 -Password $SecurePassword
    }else{
        & $PSScriptRoot/local-users.ps1 -Password $SecurePassword 
    }
} else {
    Write-Output "users.txt and admins.txt have not been filled in. Stopping."
}

& $PSScriptRoot/registry-hardening.ps1

& $PSScriptRoot/remove-nondefaultshares.ps1 
cmd /c (bcdedit /set {current} nx AlwaysOn)

$firefox = Read-Host "Is Firefox on this system? [y/n] (Default: n)"
if(($firefox -eq "Y") -or ($firefox -eq "y")){
    Write-Output "Configuring Firefox"
    & $PSScriptRoot/configure-firefox.ps1
}

& $PSScriptRoot/import-gpo.ps1

$EndTime = Get-Date
$ts = New-TimeSpan -Start $StartTime
Write-output "Elapsed Time (HH:MM:SS): $ts`n"
Stop-Transcript
Add-Content -Path "$PSScriptRoot/../logs/log.txt" "Script finished at $EndTime"