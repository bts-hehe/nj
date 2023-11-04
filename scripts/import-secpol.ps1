Write-Output "`n---Configuring Local Security Policy"
$pwd = $MyInvocation.MyCommand.Path

$dir ="$pwd\..\..\secpol\secpol.inf" #annoying_secpol.inf
Write-Output "Importing Security Policy at $dir" 
secedit.exe /configure /db C:\Windows\security\local.sdb /cfg $dir