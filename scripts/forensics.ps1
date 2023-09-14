param($DisplayLog)
Write-Output "`n---Conducting System Forensics"
<#
- determine what OS/version this windows is
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