$gpresultOutput = (gpresult /r)
$gpresultOutput | Set-Content -Path "../logs/gpresult.txt"
# ^somehow parse this properly

Foreach ($gpoitem in Get-ChildItem ".\GPOs") {
    Write-Output "Importing Group Policy $gpoitem"
    $PSScriptRoot/LGPO.exe /g GPOs\$gpoitem
}
gpupdate /force