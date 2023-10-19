Write-Output "`n---Configuring Group Policy"
$gpresultOutput = (gpresult /r)
$gpresultOutput | Set-Content -Path "$PSScriptRoot/../logs/gpresult.txt"
# ^somehow parse this properly

Foreach ($gpoitem in Get-ChildItem ".\../GPOs") {
    Write-Output "Importing Group Policy $gpoitem"
    #$PSScriptRoot/LGPO.exe /g "..GPOs\$gpoitem"
    cmd /c LGPO.exe /g ../GPOs
}
gpupdate /force
