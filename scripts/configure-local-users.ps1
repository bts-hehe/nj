param ($Password)

Disable-LocalUser -Name "Administrator"
Disable-LocalUser -Name "Guest"
Disable-LocalUser -Name "DefaultAccount"

Get-LocalGroupMember "Remote Desktop Users" | ForEach-Object {Remove-LocalGroupMember "Remote Desktop Users" $_ -Confirm:$false}
Get-LocalGroupMember "Remote Management Users" | ForEach-Object {Remove-LocalGroupMember "Remote Management Users" $_ -Confirm:$false}

$UsersOnImage = Get-LocalUser | Select-Object -ExpandProperty name
$Users = Get-Content -Path "users.txt"
$Admins = Get-Content -Path "admins.txt"
Add-Content -Path "users.txt " -Value $Admins

foreach($User in $Users) {
    if (-not((Get-LocalUser).Name -Contains $User)){ # if user doesn't exist
        Write-Output "Adding user $User"
        New-LocalUser -Name $User -Password $Password
    }
}
foreach($Admin in $Admins) {
    if (-not((Get-LocalUser).Name -Contains $Admin)){ # if admin doesn't exist
        Write-Output "Adding admin $Admin"
        New-LocalUser -Name $Admin -Password $Password
    }
}
Get-LocalUser | Set-LocalUser -Password $Password 
foreach($User in $UsersOnImage) {
    $SEL = Select-String -Path "users.txt" -Pattern $User
    if ($null -ne $SEL){ # if user is authorized
        Enable-LocalUser $User
    }else{
        Write-Output "Disabling user $User"
        Disable-LocalUser $User
    }
}
foreach($User in $UsersOnImage) {
    $SEL = Select-String -Path "admins.txt" -Pattern $User
    if ($null -ne $SEL){ # if user is auth admin 
        Add-LocalGroupMember -Group "Administrators" -Member $User 
        Enable-LocalUser $User
    }else{
        Remove-LocalGroupMember -Group "Administrators" -Member $User
    }
}