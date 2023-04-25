Get-LocalUser | Set-LocalUser -Password (Read-Host -AsSecureString "Local Pass: ")
Get-ADUser | Set-ADUser -Password (Read-Host -AsSecureString "AD pass: ")
