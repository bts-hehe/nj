param (
    [Parameter(Mandatory)]
    [SecureString] $Password
)
Write-Output "`n---Configuring AD Users"

Disable-ADAccount "Administrator"
Disable-ADAccount "Guest"
Disable-ADAccount "DefaultAccount"

$Users = Get-Content -Path "$PSScriptRoot/../users.txt" # list of authorized AD users from readme
$Admins = Get-Content -Path "$PSScriptRoot/../admins.txt" # list of authorized AD admins from readme
# at this point, assumes configure-local-users has already been run, bc it needs users.txt to also contain admins.txt list

$DomainUsersOnImage = Get-ADUser -Filter * | Select-Object -ExpandProperty name
Set-Content -Path "$PSScriptRoot/../logs/initial-ad-users.txt" $DomainUsersOnImage # log initial AD users on image to file in case we mess up or wanna check smth

foreach($DomainUser in $DomainUsers) {
    if ($UsersOnImage -notcontains $DomainUser){ # if user doesn't exist
        Write-Output "Adding Domain User $DomainUser"
        New-ADUser -Name $DomainUser -Password $Password
    }
}
foreach($DomainUser in $DomainUsersOnImage) {
    if ($Users -contains $DomainUser){ # if user is authorized because the username was found in users.txt
        Enable-ADAccount -Identity $DomainUser
        Write-Output "Enabling user $DomainUser"
    }else{
        Write-Output "Disabling user $DomainUser"
        Disable-ADAccount $DomainUser
    }
}
foreach($DomainAdmin in $DomainUsersOnImage) {
    if ($Admins -contains $DomainAdmin){ # if user is authorized domain admin because username was found in admins.txt 
        Enable-ADAccount -Identity $DomainUser
        Add-ADGroupMember -Identity "Domain Admins" -Members $DomainAdmin
        Write-Output "Adding user $DomainAdmin to admin" 
    }else{
        Remove-ADGroupMember -Identity "Domain Admins" -Members $DomainAdmin
        Write-Output "Removing user $DomainAdmin from admin" 
    }
}
Get-ADUser -Filter *| Set-ADAccountPassword -NewPassword $Password
Get-ADUser -Filter *| Set-ADUser -PasswordNeverExpires:$false
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true ' | Set-ADAccountControl -doesnotrequirepreauth $false # defend against AS_REP Roasting
