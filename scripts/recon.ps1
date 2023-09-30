param($DisplayLog)
Write-Output "`n---Collecting System Info"
<#
- determine what OS/version this windows is
- does this computer have AD server?
- get initial list of users, admins (ad or local depending on server/workstation)
- log to recon.txt
#>

#systeminfo.exe
Start-Transcript -Append ../logs/forensics.txt
$OS = Get-ComputerInfo | Select-Object -ExpandProperty OSName

Stop-Transcript
if($DisplayLog) {
    Get-Content ../logs/forensics.txt
}
