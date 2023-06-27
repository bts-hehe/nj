write-output "|| starting script ||"

# ---ENABLING FIREWALL---
Set-Service mpssvc -StartupType Automatic
Start-Service mpssvc
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow

# ---DISABLING GUEST/ADMINISTRATOR ACCOUNTS---
Disable-LocalUser -Name "Administrator"
Disable-LocalUser -Name "Guest"

# ---USERS---
Get-LocalGroupMember "Remote Desktop Users" | ForEach-Object {Remove-LocalGroupMember "Remote Desktop Users" $_ -Confirm:$false}
Get-LocalGroupMember "Remote Management Users" | ForEach-Object {Remove-LocalGroupMember "Remote Management Users" $_ -Confirm:$false}

$Users = Get-ChildItem "C:\Users"
$Password = "CyberPatriot123!@#"

Get-LocalUser | Set-LocalUser -Password $Password 
foreach($User in $Users) {
    $SEL = Select-String -Path "users.txt" -Pattern $User
    if ($null -ne $SEL){ # if user is auth 
        Enable-LocalUser $User
    }else{
        Disable-LocalUser $User
    }
}
foreach($user in $users) {
    $SEL = Select-String -Path "admins.txt" -Pattern $user
    if ($null -ne $SEL){ # if user is auth admin 
        Add-LocalGroupMember -Group "Administrators" -Member $user 
    }else{
        Remove-LocalGroupMember -Group "Administrators" -Member $user
    }
}

# ---UAC---
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v FilterAdministratorToken /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableUIADesktopToggle /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v ConsentPromptBehaviorUser /d 0 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v ValidateAdminCodeSignatures /d 1 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableSecureUIAPaths /d 1 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableLUA /d 1 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableVirtualization /d 0 /f 

# ---AUDIT POLICY---
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"DS Access" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable

# ---IMPORTING SECPOL.INF---
$dir ='secpol.inf'
secedit.exe /configure /db %windir%\security\local.sdb /cfg $dir

# ---WINDOWS DEFENDER---
Remove-MpPreference -ExclusionPath ( Get-MpPreference | Select-Object -Property ExclusionPath -ExpandProperty ExclusionPath)

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /F

# ---MISC HARDENING---
net share C:\ /delete
bcdedit /set {current} nx AlwaysOn

reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile /v EnableFirewall /t REG_DWORD /d 1 /f # enable firewall
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System /t REG_DWORD /v EnableSmartScreen /d 1 /f # enable smartscreen, this is a problem if downloading software
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers  /v DisableAutoplay /t REG_DWORD /d 1 /f # disable autoplay
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f # enable autoupdate
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 3 /f # enable autoupdate
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f # user cannot request remote assistance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /t REG_DWORD /v fDenyTSConnections /d 0 /f # disable remote desktop
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"/t REG_DWORD /v fSingleSessionPerUser /d 1 /f # disable auto admin login
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Autoadminlogin /t REG_SZ /d 0 /f # disable auto admin login
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DisableCAD /t REG_DWORD /d 1 /f # disable ctrl-alt-delete to login
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f # disable WDigest
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f # enable RDP NLA (network level auth)
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v LdapEnforceChannelBinding /t REG_DWORD /d 1 /f # make LDAP authentication over SSL/TLS more secure

# ---DISABLING FEATURES/SERVICES---
./services.bat
Disable-PSRemoting -Force

# TelnetClient, TelnetServer, SMB1Protocol

write-output "|| finishing script ||"