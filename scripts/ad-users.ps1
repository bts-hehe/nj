param (
    [Parameter(Mandatory)]
    [SecureString] $Password
)
Write-Output "`n---Configuring AD Users"

Disable-ADAccount "Administrator"
Disable-ADAccount "Guest"
Disable-ADAccount "DefaultAccount"

$DomainUsers = Get-Content -Path "$PSScriptRoot/../users.txt" # list of authorized AD users from readme
$DomainAdmins = Get-Content -Path "$PSScriptRoot/../admins.txt" # list of authorized AD admins from readme
# at this point, assumes configure-local-users has already been run, bc it needs users.txt to also contain admins.txt list

$DomainUsersOnImage = Get-ADUser -Filter * | Select-Object -ExpandProperty name
Set-Content -Path "$PSScriptRoot/../logs/initial-ad-users.txt" $DomainUsersOnImage # log initial AD users on image to file in case we mess up or wanna check smth

foreach($DomainUser in $DomainUsers) {
    if ($DomainUsersOnImage -notcontains $DomainUser){ # if user doesn't exist
        Write-Output "Adding Domain User $DomainUser"
        New-ADUser -Name $DomainUser 
    }
}

foreach($DomainUser in $DomainAdmins) {
    if ($DomainUsersOnImage -notcontains $DomainUser){ # if user doesn't exist
        Write-Output "Adding Domain User $DomainUser"
        New-ADUser -Name $DomainUser 
    }
}

$DomainUsersOnImage = Get-ADUser -Filter * | Select-Object -ExpandProperty name

foreach($DomainUser in $DomainUsersOnImage) {
    if (!($DomainUsers -contains $DomainUser) -and !($DomainAdmins -contains $DomainUser)){
        Write-Output "Disabling user $DomainUser"
        Disable-ADAccount $DomainUser
    } else {
        Enable-ADAccount -Identity $DomainUser
        Write-Output "Enabling user $DomainUser"
    }
}

$AdminsOnImage = (Get-ADGroupMember -Identity "Domain Admins").name
foreach($DomainUser in $DomainUsersOnImage) {
    if ($DomainAdmins -contains $DomainUser){ # if user is authorized domain admin because username was found in admins.txt 
        if(!($AdminsOnImage -contains ($DomainUser))){ # if user is auth admin and is not already added
            Write-Output "Adding $User to Administrators Group"
            Add-ADGroupMember -Identity "Domain Admins" -Members $DomainUser
    }}elseif(($AdminsOnImage -contains ($DomainUser)) -and ($User -ne 'Administrator')){ # if user is unauthorized, in admin group, and is not 'Administrator'
        Remove-ADGroupMember -Identity "Domain Admins" -Members $DomainUser
        Write-Output "Removing user $DomainUser from admin" 
    }
}
Get-ADUser -Filter *| Set-ADAccountPassword -NewPassword $Password
Get-ADUser -Filter *| Set-ADUser -PasswordNeverExpires:$false
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true ' | Set-ADAccountControl -doesnotrequirepreauth $false # defend against AS_REP Roasting
