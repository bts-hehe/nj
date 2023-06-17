[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
write-output "importing secpol.inf file, make sure connected to internet"
$dir ='C:\temp\secpol.inf'
Invoke-WebRequest 'https://raw.githubusercontent.com/prince-of-tennis/delphinium/main/secpol.inf' -OutFile $dir
secedit.exe /configure /db %windir%\security\local.sdb /cfg $dir
secedit.exe /configure /db %windir%\security\local.sdb /cfg D:\security-policy.inf

