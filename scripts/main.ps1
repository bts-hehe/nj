# functions ---

function Set-Features {
    Disable-PSRemoting -Force
    Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient
    Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
}
function Set-UAC {
    Write-Output "Setting UAC"
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v FilterAdministratorToken /d 1 /f
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableUIADesktopToggle /d 0 /f
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v ConsentPromptBehaviorUser /d 0 /f 
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v ValidateAdminCodeSignatures /d 1 /f 
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableSecureUIAPaths /d 1 /f 
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableLUA /d 1 /f 
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v EnableVirtualization /d 0 /f 
}
function Set-AuditPolicy {
    Write-Output "Setting Audit Policy"
    auditpol /set /category:"Account Logon" /success:enable /failure:enable
    auditpol /set /category:"Account Management" /success:enable /failure:enable
    auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
    auditpol /set /category:"DS Access" /success:enable /failure:enable
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Object Access" /success:enable /failure:enable
    auditpol /set /category:"Policy Change" /success:enable /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable
    auditpol /set /category:"System" /success:enable /failure:enable
}
function Invoke-RemoveNonDefaultSMBShares {
    Write-Output "Removing every share besides ADMIN$, C$, and IPC$"
    $Shares = Get-SmbShare | Select-Object -ExpandProperty name
    foreach($Share in $Shares) {
        if(($Share -ne "ADMIN$") -and ($Share -ne "C$") -and ($Share -ne "IPC$")) {
            Write-Output "Removed share $Share"
            Remove-SmbShare -Name $Share
        }
    }
    # maybe check folder paths to see if they're ACTUALLY default?
}
function Invoke-MiscellaneousHardening {
    bcdedit /set {current} nx AlwaysOn

    reg add"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v EnableSmartScreen /d 1 /f # enable smartscreen, this is a problem if downloading software
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

    # HKLM\System\CurrentControlSet\Services\DNS\Parameters\SecureResponses
}

Start-Transcript -Append log.txt
Write-Output "|| Welcome to Win ||"

Enable-WindowsDefender

$PSScriptRoot/enable-firewall.ps1
$PSScriptRoot/enable-defender.ps1

$SecurePassword = ConvertTo-SecureString -String 'CyberPatriot123!@#' -AsPlainText -Force
$PSScriptRoot/configure-local-users.ps1 -Password $SecurePassword
$PSScriptRoot/configure-ad-users.ps1 -Password $SecurePassword

$PSScriptRoot/import-gpo.ps1
$PSScriptRoot/import-secpol.ps1

$PSScriptRoot/configure-services -keepRD $true

Set-AuditPolicy
Set-UAC
Set-Features
Invoke-RemoveNonDefaultSMBShares
Invoke-MiscellaneousHardening

Write-Output "|| ccs.ps1 finished ||"
Stop-Transcript
Invoke-Item ".\log.txt"