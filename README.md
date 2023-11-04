# win
This is a script meant to harden your Windows server or workstation.

## instructions
1. Download as zip. It'll be named ```win-main```.
2. Edit the `users.txt` and `admins.txt` files. If there's some Windows system critical services, possibly edit the `enabled_services.txt` or `disabled_services.txt` files. The script will ask you if you want to enable and configure RDP, FTP, and SMB.
3. Run the following in a Powershell terminal with administrative privileges:
```powershell
Set-ExecutionPolicy Unrestricted -Confirm -Force
.\scripts\main.ps1
```
The output will be logged to `log.txt` which is opened automatically when the script is done. 

## References
- [SMB Hardening](https://github.com/ojas623/CYEE-scripts/blob/main/Windows%2010/application%20security/smbConfig.ps1)