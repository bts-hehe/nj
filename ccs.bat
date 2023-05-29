
:: UAC
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v FilterAdministratorToken /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableUIADesktopToggle /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v ConsentPromptBehaviorUser /d 0 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v ValidateAdminCodeSignatures /d 1 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableSecureUIAPaths /d 1 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableLUA /d 1 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableVirtualization /d 0 /f 

:: unshare C: drive
net share C:\ /delete

:: enable firewall
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile /v EnableFirewall /t REG_DWORD /d 1
:: enable smartscreen, this is a problem if downloading software
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System /t REG_DWORD /v EnableSmartScreen /d 1 /f
:: disable autoplay
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers  /v DisableAutoplay /t REG_DWORD /d 1
:: enable autoupdate
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 3
:: user cannot request assistance from a friend or a support professional.
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance /v fAllowToGetHelp /t REG_DWORD /d 0
:: enabling firewall via registry
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile /v EnableFirewall /t REG_DWORD /d 1
::disable remote desktop
reg add HKLM\SYSTEM\CurrentControlSet\Control\"Terminal Server" /t REG_DWORD /v fDenyTSConnections /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\"Terminal Server"/t REG_DWORD /v fSingleSessionPerUser /d 1 /f
:: disable auto admin login
reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v Autoadminlogin /t REG_SZ /d 0 /f
:: disable ctrl-alt-delete to login
reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v DisableCAD /t REG_DWORD /d 1 /f
:: disable WDigest
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0
:: enable RDP NLA (network level auth)
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp /v UserAuthentication /t REG_DWORD /d 1
:: make LDAP authentication over SSL/TLS more secure
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v LdapEnforceChannelBinding /t REG_DWORD /d 1
