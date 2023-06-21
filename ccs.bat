@echo off
echo "|| starting script ||"

netsh advfirewall set allprofiles state on

:: users
net user administrator /active:no
net user guest /active:no

set password="CyberPatriot123!@#"

FOR /F "TOKENS=*" %%F IN (%USERPROFILE%\Desktop\users.txt) DO (
  net user %%~F $password
  net user /domain %%~F /ACTIVE YES
) 
FOR /F "TOKENS=*" %%F IN (%USERPROFILE%\Desktop\admins.txt) DO (
  net user %%~F $password
  net user /domain %%~F /ACTIVE YES
)

:: ---MISC HARDENING
net share C:\ /delete
bcdedit /set {current} nx AlwaysOn

:: ---UAC---
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v FilterAdministratorToken /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableUIADesktopToggle /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v ConsentPromptBehaviorUser /d 0 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v ValidateAdminCodeSignatures /d 1 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableSecureUIAPaths /d 1 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableLUA /d 1 /f 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableVirtualization /d 0 /f 

:: ---AUDIT POLICY---
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"DS Access" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable

:: ---DEFENDER---
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

:: ---APP SECURITY---
HKLM\System\CurrentControlSet\Services\DNS\Parameters\SecureResponses






:: ---SERVICES---
sc config "NTDS" start= disabled
sc config "ADWS" start= disabled
sc config "ALG" start= disabled
sc config "tzautoupdate" start= disabled
sc config "BTAGService" start= disabled
sc config "bthserv" start= disabled
sc config "MapsBroker" start= disabled
sc config "lfsvc" start= disabled
sc config "HvHost" start= disabled
sc config "vmickvpexchange" start= disabled
sc config "vmicguestinterface" start= disabled
sc config "vmicshutdown" start= disabled
sc config "vmicheartbeat" start= disabled
sc config "vmicvmsession" start= disabled
sc config "vmicrdv" start= disabled
sc config "vmictimesync" start= disabled
sc config "vmicvss" start= disabled
sc config "SharedAccess" start= disabled
sc config "IsmServ" start= disabled
sc config "iphlpsvc" start= disabled
sc config "Kdc" start= disabled
sc config "AppVClient" start= disabled
sc config "MSiSCSI" start= disabled
sc config "NetTcpPortSharing" start= disabled
sc config "CscService" start= disabled
sc config "SEMgrSvc" start= disabled
sc config "PhoneSvc" start= disabled
sc config "wercplsupport" start= disabled
sc config "RasAuto" start= disabled
sc config "RasMan" start= disabled
sc config "RemoteRegistry" start= disabled
sc config "RemoteAccess" start= disabled
sc config "SensorDataService" start= disabled
sc config "SensrSvc" start= disabled
sc config "SensorService" start= disabled
sc config "shpamsvc" start= disabled
sc config "SCardSvr" start= disabled
sc config "ScDeviceEnum" start= disabled
sc config "SCPolicySvc" start= disabled
sc config "SNMPTRAP" start= disabled
sc config "SSDPSRV" start= disabled
sc config "lmhosts" start= disabled
sc config "tapisrv" start= disabled
sc config "UevAgentService" start= disabled
sc config "FrameServer" start= disabled
sc config "wisvc" start= disabled
sc config "icssvc" start= disabled
sc config "WinRM" start= disabled
sc config "simptcp" start= disabled
sc config "TlntSvr" start= disabled
sc config "upnphost" start= disabled
sc config "ftpsvc" start= disabled
sc config "PeerDistSvc" start= disabled
sc config "CertPropSvc" start= disabled
 
sc config "BFE" start= auto
sc config "BDESVC" start= auto
sc config "CryptSvc" start= auto
sc config "DcomLaunch" start= auto
sc config "Dhcp" start= auto
sc config "DPS" start= auto
sc config "TrkWks" start= auto
sc config "Dnscache" start= auto
sc config "gpsvc" start= auto
sc config "Spooler" start= auto
sc config "PcaSvc" start= auto
sc config "ProtectedStorage" start= auto
sc config "RpcSs" start= auto
sc config "RpcLocator" start= auto
sc config "RpcEptMapper" start= auto
sc config "SamSs" start= auto
sc config "wscsvc" start= auto
sc config "sppsvc" start= auto
sc config "Schedule" start= auto
sc config "WinDefend" start= auto
sc config "wudfsvc" start= auto
sc config "EventLog" start= auto
sc config "MpsSvc" start= auto
sc config "wuauserv" start= auto
sc config "WerSvc" start= auto
sc config "Wecsvc" start= auto
sc config "Power" start= auto
sc config "PlugPlay" start= auto
sc config "AppHostSvc" start= auto
sc config "BrokerInfrastructure" start= auto
sc config "EventSystem" start= auto
sc config "DiagTrack" start= auto
sc config "CoreMessagingRegistrar" start= auto
sc config "Dfs" start= auto
sc config "DFSR" start= auto
sc config "DNS" start= auto
sc config "IISADMIN" start= auto
sc config "LSM" start= auto
sc config "NlaSvc" start= auto
sc config "nsi" start= auto
sc config "ShellHWDetection" start= auto
sc config "SysMain" start= auto
sc config "SENS" start= auto
sc config "upnphost" start= auto
sc config "ProfSvc" start= auto
sc config "ServerManagementGateway" start= auto
sc config "Audiosrv" start= auto
sc config "AudioEndpointBuilder" start= auto
sc config "FontCache" start= auto
sc config "WLMS" start= auto
sc config "Winmgmt" start= auto
sc config "WpnService" start= auto
sc config "LanmanWorkstation" start= auto
sc config "W3SVC" start= auto
sc config "UALSVC" start= auto
sc config "WSearch" start= auto
sc config "UsoSvc" start= auto
sc config "CDPSvc" start= auto
sc config "IKEEXT" start= auto
sc config "SystemEventsBroker" start= auto
sc config "UserManager" start= auto
sc config "Wcmsvc" start= auto
sc config "WEPHOSTSVC" start= auto
sc config "LicenseManager" start= auto
sc config "W32Time" start= auto
sc config "CDPSvc" start= auto
sc config "IKEEXT" start= auto
sc config "SystemEventsBroker" start= auto
sc config "UserManager" start= auto
sc config "Wcmsvc" start= auto
sc config "WEPHOSTSVC" start= auto
sc config "LicenseManager" start= auto
sc config "W32Time" start= auto

sc stop "NTDS"
sc stop "ADWS"
sc stop "ALG"
sc stop "tzautoupdate"
sc stop "BTAGService"
sc stop "bthserv"
sc stop "MapsBroker"
sc stop "lfsvc"
sc stop "HvHost"
sc stop "vmickvpexchange"
sc stop "vmicguestinterface"
sc stop "vmicshutdown"
sc stop "vmicheartbeat"
sc stop "vmicvmsession"
sc stop "vmicrdv"
sc stop "vmictimesync"
sc stop "vmicvss"
sc stop "SharedAccess"
sc stop "IsmServ"
sc stop "iphlpsvc"
sc stop "Kdc"
sc stop "AppVClient"
sc stop "MSiSCSI"
sc stop "NetTcpPortSharing"
sc stop "CscService"
sc stop "SEMgrSvc"
sc stop "PhoneSvc"
sc stop "wercplsupport"
sc stop "RasAuto"
sc stop "RasMan"
sc stop "RemoteRegistry"
sc stop "RemoteAccess"
sc stop "SensorDataService"
sc stop "SensrSvc"
sc stop "SensorService"
sc stop "shpamsvc"
sc stop "SCardSvr"
sc stop "ScDeviceEnum"
sc stop "SCPolicySvc"
sc stop "SNMPTRAP"
sc stop "SSDPSRV"
sc stop "lmhosts"
sc stop "tapisrv"
sc stop "UevAgentService"
sc stop "FrameServer"
sc stop "wisvc"
sc stop "icssvc"
sc stop "WinRM"
sc stop "simptcp"
sc stop "TlntSvr"
sc stop "upnphost"
sc stop "ftpsvc"
sc stop "PeerDistSvc"
sc stop "CertPropSvc"

sc start "BFE"
sc start "BDESVC"
sc start "CryptSvc"
sc start "DcomLaunch"
sc start "Dhcp"
sc start "DPS"
sc start "TrkWks"
sc start "Dnscache"
sc start "gpsvc"
sc start "Spooler"
sc start "PcaSvc"
sc start "ProtectedStorage"
sc start "RpcSs"
sc start "RpcLocator"
sc start "RpcEptMapper"
sc start "SamSs"
sc start "wscsvc"
sc start "sppsvc"
sc start "Schedule"
sc start "WinDefend"
sc start "wudfsvc"
sc start "EventLog"
sc start "MpsSvc"
sc start "wuauserv"
sc start "WerSvc"
sc start "Wecsvc"
sc start "Power"
sc start "PlugPlay"
sc start "AppHostSvc"
sc start "BrokerInfrastructure"
sc start "EventSystem"
sc start "DiagTrack"
sc start "CoreMessagingRegistrar"
sc start "Dfs"
sc start "DFSR"
sc start "DNS"
sc start "IISADMIN"
sc start "LSM"
sc start "NlaSvc"
sc start "nsi"
sc start "ShellHWDetection"
sc start "SysMain"
sc start "SENS"
sc start "upnphost"
sc start "ProfSvc"
sc start "ServerManagementGateway"
sc start "Audiosrv"
sc start "AudioEndpointBuilder"
sc start "FontCache"
sc start "WLMS"
sc start "Winmgmt"
sc start "WpnService"
sc start "LanmanWorkstation"
sc start "W3SVC"
sc start "UALSVC"
sc start "WSearch"
sc start "UsoSvc"
sc start "CDPSvc"
sc start "IKEEXT"
sc start "SystemEventsBroker"
sc start "UserManager"
sc start "Wcmsvc"
sc start "WEPHOSTSVC"
sc start "LicenseManager"
sc start "W32Time"
sc start "CDPSvc"
sc start "IKEEXT"
sc start "SystemEventsBroker"
sc start "UserManager"
sc start "Wcmsvc"
sc start "WEPHOSTSVC"
sc start "LicenseManager"
sc start "W32Time"

echo "|| finishing script ||"