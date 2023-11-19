param (
    [Parameter(Mandatory)]
    [int] $productType
)
$services = (reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services)
foreach($line in $services){
    ($line -split "\\")[4] >> $PSScriptRoot/baseline/image-services.txt
}

if($productType -eq 1){
    Write-Output (compare-object (get-content $PSScriptRoot/baseline/services.txt) (get-content $PSScriptRoot/baseline/win10-default-services.txt))
} else {
    $serverVersion = Read-Host "Server 19 or 22?: [19/22] (Default: 22)"
    if(($serverVersion -eq "19")){
        Write-Output (compare-object (get-content $PSScriptRoot/baseline/services.txt) (get-content $PSScriptRoot/baseline/server19-default-services.txt))
    } else {
        Write-Output (compare-object (get-content $PSScriptRoot/baseline/services.txt) (get-content $PSScriptRoot/baseline/server22-default-services.txt))
    }
}
