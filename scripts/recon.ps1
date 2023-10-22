Write-Output "`n---Collecting System Info"
<#
- determine what OS/version this windows is
- does this computer have AD server?
- get initial list of users, admins (ad or local depending on server/workstation)
- log to recon.txt
#>

#systeminfo.exe
Get-ComputerInfo | Select-Object -ExpandProperty OSName | Out-File -FilePath $PSScriptRoot/../logs/os.txt

if(-not((Get-Content (Get-PSReadlineOption).HistorySavePath) -eq $null)){
  Get-Content (Get-PSReadlineOption).HistorySavePath | Out-File -FilePath $PSScriptRoot/../logs/pshistory.txt
}
