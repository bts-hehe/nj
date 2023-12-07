# win
This is a script meant to harden your windows server or workstation.

## instructions
1. Download as zip. It'll be named ```win-main```.
  2. Edit the `users.txt` and `admins.txt` files. If there's some Windows system critical services, possibly edit the `enabled_services.txt` or `disabled_services.txt` files. The script will ask you if you want to enable and configure RDP, FTP, and SMB.
  3. Run the following in a Powershell terminal with administrative privileges:
  ```powershell
  Set-ExecutionPolicy Unrestricted -Confirm -Force
  .\scripts\main.ps1
  ```
  The script will try to import a GPO last. You can start doing your own thing by then, even before the GPO finishes importing. The output will be logged to `log.txt` in the `logs` folder. 

If you want to look for media files, run `media.bat`, which will log to a folder on your user's desktop.

## References
