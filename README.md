# win
This is a script meant to harden your windows server or workstation.

## Running the script
### CCS-style competition 
  1. Download as zip or clone to C: as a folder that should be named ```win-main```.
  2. Edit the `users.txt` and `admins.txt` files. If there's some services to configure, look into the `enabled_services.txt` or `disabled_services.txt` files.
  2. Run the following in a Powershell terminal with administrative privileges:
  ```powershell
  Set-ExecutionPolicy Unrestricted -force
  ```
  3. Run the `ccs.ps1` file.
  4. remember to delete folder once you are done

### RvB competitions
**TODO**
```powershell
Get-LocalUser | Set-LocalUser -Password (Read-Host -AsSecureString "Local Pass: ")
Get-ADUser | Set-ADUser -Password (Read-Host -AsSecureString "AD pass: ")
```
## Overview of `CCS.ps1`

## Version Notes
- doesn't currently work for Active Directory (users)
