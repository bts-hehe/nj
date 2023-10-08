param (
    [Parameter(Mandatory)]
    [SecureString] $Password
)
Write-Output "`n---Configuring Local Users"
Disable-LocalUser -Name "Administrator"
Disable-LocalUser -Name "Guest"
Disable-LocalUser -Name "DefaultAccount"

$Users = Get-Content -Path "users.txt"
$Admins = Get-Content -Path "admins.txt"
Add-Content -Path "users.txt " -Value $Admins # the list of admins is added to the users list so that admins that don't exist yet are also created

$UsersOnImage = Get-LocalUser | Select-Object -ExpandProperty name
Set-Content -Path ../logs/initial-local-users.txt $UsersOnImage # log initial local users on image to file in case we mess up or wanna check smth

foreach($User in $Users) {
    if ($UsersOnImage -notcontains $User){
        Write-Output "Adding user $User"
        New-LocalUser -Name $User -Password $Password -PasswordNeverExpires $false -UserMayChangePassword $true
    }
}
Get-LocalUser | Set-LocalUser -Password $Password # set everyone's password
foreach($User in $UsersOnImage) {
    if ($Users -contains $User){ # if user is authorized
        Enable-LocalUser $User
    }else{
        Write-Output "Disabling user $User"
        Disable-LocalUser $User
    }
}
foreach($User in $UsersOnImage) {
    if ($Admins -contains $Users){ # if user is auth admin 
        Add-LocalGroupMember -Group "Administrators" -Member $User 
    }else{
        Remove-LocalGroupMember -Group "Administrators" -Member $User
    }
}