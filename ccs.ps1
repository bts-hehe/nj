write-output "|| starting script ||"

# ---ENABLING FIREWALL---
Set-Service mpssvc -StartupType Automatic
Start-Service mpssvc
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow

#Disable-NetFirewallRule -group "Remote Assistance"

# ---DISABLING GUEST/ADMINISTRATOR ACCOUNTS---
Disable-LocalUser -Name "Administrator"
Disable-LocalUser -Name "Guest"

#Disable-ADAccount -Name "Administrator"
#Disable-ADAccount -Name "Guest"

# ---ENABLING/DISABLING USER ACCOUNTS, REMOVING EVERYONE FROM ADMINS---
write-output "RMBR TO CREATE admins.txt, users.txt -> C:\temp\admins.txt"

# disable remote desktop, remote mgmt?
Get-LocalGroupMember "Remote Desktop Users" | ForEach-Object {Remove-LocalGroupMember "Remote Desktop Users" $_ -Confirm:$false}
Get-LocalGroupMember "Remote Management Users" | ForEach-Object {Remove-LocalGroupMember "Remote Management Users" $_ -Confirm:$false}

$users = Get-ChildItem "C:\Users"
foreach($user in $users) {
    $SEL = Select-String -Path C:\temp\users.txt -Pattern $user
    if ($null -ne $SEL){ # if user is auth 
        Enable-LocalUser $user
        #Enable-ADAccount $user
    }else{
        Disable-LocalUser $user
        #Disable-ADAccount $user
    }
}
foreach($user in $users) {
    $SEL = Select-String -Path C:\temp\admins.txt -Pattern $user
    if ($null -ne $SEL){ # if user is auth admin 
        Add-LocalGroupMember -Group "Administrators" -Member $user 
        #Add-ADGroupMember - Group "Administrators" - Member $user
    }else{
        Remove-LocalGroupMember -Group "Administrators" -Member $user
        #Remove-ADGroupMember -Group "Administrators" -Member $user
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
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
write-output "importing secpol.inf file, make sure connected to internet"
$dir ='C:\temp\secpol.inf'
Invoke-WebRequest 'https://raw.githubusercontent.com/prince-of-tennis/delphinium/main/secpol.inf' -OutFile $dir
secedit.exe /configure /db %windir%\security\local.sdb /cfg $dir

# ---WINDOWS DEFENDER---
Set-Service WinDefend -StartupType Automatic
Start-Service WinDefend

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

# unshare C: drive
net share C:\ /delete
# enable Data Execution Prevention
bcdedit /set {current} nx AlwaysOn # look into this

# enable firewall
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile /v EnableFirewall /t REG_DWORD /d 1 /f
# enable smartscreen, this is a problem if downloading software
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System /t REG_DWORD /v EnableSmartScreen /d 1 /f
# disable autoplay
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers  /v DisableAutoplay /t REG_DWORD /d 1 /f
# enable autoupdate
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 3 /f
# user cannot request assistance from a friend or a support professional.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
# disable remote desktop
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /t REG_DWORD /v fDenyTSConnections /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"/t REG_DWORD /v fSingleSessionPerUser /d 1 /f
# disable auto admin login
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Autoadminlogin /t REG_SZ /d 0 /f
# disable ctrl-alt-delete to login
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DisableCAD /t REG_DWORD /d 1 /f
# disable WDigest
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f
# enable RDP NLA (network level auth)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
# make LDAP authentication over SSL/TLS more secure
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v LdapEnforceChannelBinding /t REG_DWORD /d 1 /f

# ---DISABLING FEATURES/SERVICES---
write-output "beginning to disable services - check readme for critical services"

Set-Service snmptrap -StartupType Disabled
Stop-Service snmptrap 
Set-Service WinRM -StartupType Disabled
Stop-Service WinRM 
Set-Service WSearch -StartupType Disabled
Stop-Service WSearch
Set-Service iphlpsvc -StartupType Disabled
Stop-Service iphlpsvc 

Disable-PSRemoting -Force
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart  
Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer -NoRestart  

Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart  
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 

# ---ENABLING FEATURES/SERVICES---
Set-Service W32Time -StartupType Automatic
Start-Service W32Time

#Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force

# ---SETTING LOCAL/DOMAIN PASSWORDS---
Get-LocalUser | Set-LocalUser -Password (Read-Host -AsSecureString "local pass: ")
Get-ADUser | Set-ADUser -Password (Read-Host -AsSecureString "AD pass:")

write-output "|| finishing script ||"