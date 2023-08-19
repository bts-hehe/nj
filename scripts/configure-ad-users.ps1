param ($Password) # password is passed in as a SecureString parameter
Write-Output "`n---Configuring AD Users"

Disable-ADAccount -Name "Administrator"
Disable-ADAccount -Name "Guest"
Disable-ADAccount -Name "DefaultAccount"

$DomainUsers = Get-Content -Path "users.txt"
$DomainAdmins = Get-Content -Path "admins.txt"
# at this point, assumes configure-local-users has already been run, bc it needs users.txt to also contain admins.txt list

$DomainUsersOnImage = Get-ADAccount | Select-Object -ExpandProperty name

foreach($DomainUser in $DomainUsers) {
    if (-not((Get-ADUser).Name -Contains $DomainUser)){ # if user doesn't exist
        Write-Output "Adding Domain User $DomainUser"
        New-ADUser -Name $DomainUser -Password $Password
    }
}
Get-ADUser | Set-ADUser -Password $Password
foreach($DomainUser in $DomainUsersOnImage) {
    if ((Select-String -Path "users.txt" -Pattern $DomainUser) -ne $null){ # if user is authorized because the username was found in users.txt
        Enable-ADAccount -Identity $DomainUser
    }else{
        Write-Output "Disabling user $DomainUser"
        Disable-ADAccount $DomainUser
    }
}
foreach($DomainAdmin in $DomainUsersOnImage) {
    if ((Select-String -Path "admins.txt" -Pattern $DomainUser) -ne $null){ # if user is authorized domain admin because username was found in admins.txt 
        Enable-ADAccount -Identity $DomainUser
        Add-ADGroupMember -Group "Administrators" -Member $DomainUser 
    }else{
        Remove-ADAccount -Group "Administrators" -Member $DomainUser
    }
}