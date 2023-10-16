param (
    [Parameter(Mandatory)]
    [SecureString] $Password
)
Write-Output "`n---Configuring AD Users"

Disable-ADAccount -Name "Administrator"
Disable-ADAccount -Name "Guest"
Disable-ADAccount -Name "DefaultAccount"

$Users = Get-Content -Path "../users.txt" # list of authorized AD users from readme
$Admins = Get-Content -Path "../admins.txt" # list of authorized AD admins from readme
# at this point, assumes configure-local-users has already been run, bc it needs users.txt to also contain admins.txt list

$DomainUsersOnImage = Get-ADAccount | Select-Object -ExpandProperty name
Set-Content -Path ../logs/initial-ad-users.txt $DomainUsersOnImage # log initial AD users on image to file in case we mess up or wanna check smth

foreach($DomainUser in $DomainUsers) {
    if ($UsersOnImage -notcontains $DomainUser){ # if user doesn't exist
        Write-Output "Adding Domain User $DomainUser"
        New-ADUser -Name $DomainUser -Password $Password
    }
}
Get-ADUser | Set-ADUser -Password $Password
foreach($DomainUser in $DomainUsersOnImage) {
    if ($Users -contains $DomainUser){ # if user is authorized because the username was found in users.txt
        Enable-ADAccount -Identity $DomainUser
    }else{
        Write-Output "Disabling user $DomainUser"
        Disable-ADAccount $DomainUser
    }
}
foreach($DomainAdmin in $DomainUsersOnImage) {
    if ($Admins -contains $DomainAdmin){ # if user is authorized domain admin because username was found in admins.txt 
        Enable-ADAccount -Identity $DomainUser
        Add-ADGroupMember -Group "Administrators" -Member $DomainUser 
    }else{
        Remove-ADAccount -Group "Administrators" -Member $DomainUser
    }
}
