Write-Output "Importing secpol.inf" 
$dir ='..\secpol\secpol.inf' #annoying_secpol.inf
secedit.exe /configure /db C:\Windows\security\local.sdb /cfg $dir