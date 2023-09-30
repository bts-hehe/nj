param ($Password) # password is passed in as a SecureString parameter
Write-Output "`n---Configuring Local Users"
Disable-LocalUser -Name "Administrator"
Disable-LocalUser -Name "Guest"
Disable-LocalUser -Name "DefaultAccount"

$Users = Get-Content -Path "users.txt"
$Admins = Get-Content -Path "admins.txt"
Add-Content -Path "users.txt " -Value $Admins # the list of admins is added to the users list to make things easier

$UsersOnImage = Get-LocalUser | Select-Object -ExpandProperty name
Set-Content -Path ../logs/initial-local-users.txt $UsersOnImage # log initial AD users on image to file in case we mess up or wanna check smth

foreach($User in $Users) {
    if (-not((Get-LocalUser).Name -Contains $User)){ # if user doesn't exist
        Write-Output "Adding user $User"
        New-LocalUser -Name $User -Password $Password
    }
}
Get-LocalUser | Set-LocalUser -Password $Password # set everyone's password
foreach($User in $UsersOnImage) {
    $SEL = Select-String -Path "users.txt" -Pattern $User
    if ($SEL -ne $null){ # if user is authorized
        Enable-LocalUser $User
    }else{
        Write-Output "Disabling user $User"
        Disable-LocalUser $User
    }
}
foreach($User in $UsersOnImage) {
    $SEL = Select-String -Path "admins.txt" -Pattern $User
    if ($SEL -ne $null){ # if user is auth admin 
        Add-LocalGroupMember -Group "Administrators" -Member $User 
    }else{
        Remove-LocalGroupMember -Group "Administrators" -Member $User
    }
}