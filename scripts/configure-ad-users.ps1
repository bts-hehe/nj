$SecurePassword = ConvertTo-SecureString -String 'CyberPatriot123!@#' -AsPlainText -Force

Disable-ADAccount -Name "Administrator"
Disable-ADAccount -Name "Guest"
Disable-ADAccount -Name "DefaultAccount"

$DomainUsers = Get-ADGroupMember 'Domain Users' | Select-Object name,samaccountname
$DomainAdmins = Get-ADGroupMember 'Domain Users' | Select-Object name,samaccountname
$DomainUsersOnImage = Get-ADAccount | Select-Object -ExpandProperty name

foreach($DomainUser in $DomainUsers) {
    if (-not((Get-ADUser).Name -Contains $DomainUser)){ # if user doesn't exist
        Write-Output "Adding Domain User $DomainUser"
        New-ADUser -Name $DomainUser -Password $Password
    }
}
foreach($DomainAdmin in $DomainAdmins) {
    if (-not((Get-ADUser).Name -Contains $DomainAdmin)){ # if admin doesn't exist
        Write-Output "Adding Domain Admin $DomainAdmin"
        New-ADUser -Name $DomainAdmin -Password $Password
    }
}
Get-ADUser | Set-ADUser -Password $Password
foreach($DomainUser in $DomainUsersOnImage) {
    $SEL = Select-String -Path "users.txt" -Pattern $DomainUser
    if ($null -ne $SEL){ # if user is authorized
        Enable-ADAccount -Identity $DomainUser
    }else{
        Write-Output "Disabling user $DomainUser"
        Disable-ADAccount $DomainUser
    }
}
foreach($DomainUser in $DomainUsersOnImage) {
    $SEL = Select-String -Path "admins.txt" -Pattern $DomainUser
    if ($null -ne $SEL){ # if user is auth domain admin 
        Add-ADGroupMember -Group "Administrators" -Member $DomainUser 
        Enable-ADAccount -Identity $DomainUser
    }else{
        Remove-ADAccount -Group "Administrators" -Member $DomainUser
    }
}