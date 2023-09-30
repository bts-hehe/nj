# win
This is a script meant to harden your windows server or workstation.

## CCS-style competition 
  1. Download as zip. It'll be named ```win-main```.
  2. Edit the `users.txt` and `admins.txt` files. If there's some Windows system services to configure, look into the `enabled_services.txt` or `disabled_services.txt` files.
  3. Run the following in a Powershell terminal with administrative privileges:
  ```powershell
  Set-ExecutionPolicy Unrestricted -force
  ```
  4. Run the `main.ps1` file inside the scripts folder. The output will be logged to `log.txt` which is opened automatically when the script is done.
  5. Remember to delete the `win-main` extracted and zipped folder once you are done.

## RvB competitions
1. Download folder to local machine. Run only the password script:
```powershell
Get-LocalUser | Set-LocalUser -Password (Read-Host -AsSecureString "Local Pass: ")
Get-ADUser | Set-ADUser -Password (Read-Host -AsSecureString "AD pass: ")
```
2. If you want to do hardening, just use `ccs.ps1` and remember to configure firewall manually.

## Todo List

## Notes/References
- [SMB Hardening](https://github.com/ojas623/CYEE-scripts/blob/main/Windows%2010/application%20security/smbConfig.ps1)
