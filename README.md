# win
This is a script meant to harden your windows server or workstation.

## Running the script
### CCS-style competition 
  1. Download as zip or clone to C: as a folder. It'll be named ```win-main```.
  2. Edit the `users.txt` and `admins.txt` files. If there's some services to configure, look into the `enabled_services.txt` or `disabled_services.txt` files.
  2. Run the following in a Powershell terminal with administrative privileges:
  ```powershell
  Set-ExecutionPolicy Unrestricted -force
  ```
  3. Run the `ccs.ps1` file.
  4. remember to delete folder once you are done

### RvB competitions
1. Download folder to local machine. Run only the password script:
```powershell
Get-LocalUser | Set-LocalUser -Password (Read-Host -AsSecureString "Local Pass: ")
Get-ADUser | Set-ADUser -Password (Read-Host -AsSecureString "AD pass: ")
```
2. If you want to do hardening, just use `ccs.ps1` and remember to configure firewall manually.
## Overview of `CCS.ps1`

## Version Notes
- doesn't currently work for Active Directory (users)
- check if secpol.inf working - in theory you really only need GPO **OR** secpol.inf, preferably GPO
- need to make `backup.pol` (GPO backup) and upload here

## tehe hello 
