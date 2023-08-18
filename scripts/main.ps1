reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v EnableSmartScreen /d 1 /f # enable smartscreen, this is a problem if downloading software
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"  /v DisableAutoplay /t REG_DWORD /d 1 /f # disable autoplay
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f # enable autoupdate
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 3 /f # enable autoupdate
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f # user cannot request remote assistance
#reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /t REG_DWORD /v fDenyTSConnections /d 0 /f # disable remote desktop
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"/t REG_DWORD /v fSingleSessionPerUser /d 1 /f # disable auto admin login
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Autoadminlogin /t REG_SZ /d 0 /f # disable auto admin login
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DisableCAD /t REG_DWORD /d 1 /f # disable ctrl-alt-delete to login
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f # disable WDigest
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f # enable RDP NLA (network level auth)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 1 /f # make LDAP authentication over SSL/TLS more secure
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v TcpReceivePacketSize /t REG_DWORD /d 0xFF00 # https://support.microsoft.com/en-au/topic/kb4569509-guidance-for-dns-server-vulnerability-cve-2020-1350-6bdf3ae7-1961-2d25-7244-cce61b056569

# add this ^ stuff to secpol.inf someday
# HKLM\System\CurrentControlSet\Services\DNS\Parameters\SecureResponses

Start-Transcript -Append ../logs/log.txt
Write-Output "|| Welcome to Win ||"

$PSScriptRoot/install-tools.ps1

$PSScriptRoot/enable-firewall.ps1
$PSScriptRoot/enable-defender.ps1

$SecurePassword = ConvertTo-SecureString -String 'CyberPatriot123!@#' -AsPlainText -Force
$PSScriptRoot/configure-local-users.ps1 -Password $SecurePassword
$PSScriptRoot/configure-ad-users.ps1 -Password $SecurePassword

$PSScriptRoot/import-gpo.ps1
$PSScriptRoot/import-secpol.ps1 # if secpol breaks, run uac.ps1, auditpol.ps1

$PSScriptRoot/configure-services.ps1 -keepRD $false

bcdedit /set {current} nx AlwaysOn

Write-Output "|| ccs.ps1 finished ||"
Stop-Transcript
Invoke-Item ".../logs/log.txt"