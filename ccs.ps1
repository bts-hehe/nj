# functions ---
function Enable-Firewall {
    Write-Output "Starting Windows Defender Firewall"
    Set-Service mpssvc -StartupType Automatic
    Start-Service mpssvc
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow
}
function Set-LocalUsers([SecureString]$Password) {
    Disable-LocalUser -Name "Administrator"
    Disable-LocalUser -Name "Guest"
    Disable-LocalUser -Name "DefaultAccount"
    Get-LocalGroupMember "Remote Desktop Users" | ForEach-Object {Remove-LocalGroupMember "Remote Desktop Users" $_ -Confirm:$false}
    Get-LocalGroupMember "Remote Management Users" | ForEach-Object {Remove-LocalGroupMember "Remote Management Users" $_ -Confirm:$false}
    
    $UsersOnImage = Get-ChildItem "C:\Users"
    #$UsersOnImage = Get-LocalUser | Select-Object -ExpandProperty name
    $Users = Get-Content -Path "users.txt"
    $Admins = Get-Content -Path "admins.txt"
    foreach($User in $Users) {
        if (-not((Get-LocalUser).Name -Contains $User)){ # if user doesn't exist
            Write-Output "Adding user $User"
            New-LocalUser -Name $User -Password $Password
        }
    }
    foreach($Admin in $Admins) {
        if (-not((Get-LocalUser).Name -Contains $Admin)){ # if admin doesn't exist
            Write-Output "Adding admin $Admin"
            New-LocalUser -Name $Admin -Password $Password
        }
    }
    Get-LocalUser | Set-LocalUser -Password $Password 
    foreach($User in $UsersOnImage) {
        $SEL = Select-String -Path "users.txt" -Pattern $User
        if ($null -ne $SEL){ # if user is authorized
            Enable-LocalUser $User
        }else{
            Write-Output "Disabling user $User"
            Disable-LocalUser $User
        }
    }
    foreach($User in $UsersOnImage) {
        $SEL = Select-String -Path "admins.txt" -Pattern $User
        if ($null -ne $SEL){ # if user is auth admin 
            Add-LocalGroupMember -Group "Administrators" -Member $User 
            Enable-LocalUser $User
        }else{
            Remove-LocalGroupMember -Group "Administrators" -Member $User
        }
    }
}
function Set-ADUsers([SecureString]$Password) {
    Disable-ADAccount -Name "Administrator"
    Disable-ADAccount -Name "Guest"
    Disable-ADAccount -Name "DefaultAccount"

    $DomainUsers = Get-ADGroupMember 'Domain Users' | Select-Object name,samaccountname
    $DomainAdmins = Get-ADGroupMember 'Domain Users' | Select-Object name,samaccountname
    $DomainUsersOnImage = Get-ADAccount | Select-Object -ExpandProperty name

    foreach($DomainUser in $DomainUsers) {
        if (-not((Get-ADUser).Name -Contains $DomainUser)){ # if user doesn't exist
            Write-Output "Adding Domain User $DomainUser"
            New-ADUser -Name $DomainUser -Password $Password
        }
    }
    foreach($DomainAdmin in $DomainAdmins) {
        if (-not((Get-ADUser).Name -Contains $DomainAdmin)){ # if admin doesn't exist
            Write-Output "Adding Domain Admin $DomainAdmin"
            New-ADUser -Name $DomainAdmin -Password $Password
        }
    }
    Get-ADUser | Set-ADUser -Password $Password
    foreach($DomainUser in $DomainUsersOnImage) {
        $SEL = Select-String -Path "users.txt" -Pattern $DomainUser
        if ($null -ne $SEL){ # if user is authorized
            Enable-ADAccount -Identity $DomainUser
        }else{
            Write-Output "Disabling user $DomainUser"
            Disable-ADAccount $DomainUser
        }
    }
    foreach($DomainUser in $DomainUsersOnImage) {
        $SEL = Select-String -Path "admins.txt" -Pattern $DomainUser
        if ($null -ne $SEL){ # if user is auth domain admin 
            Add-ADGroupMember -Group "Administrators" -Member $DomainUser 
            Enable-ADAccount -Identity $DomainUser
        }else{
            Remove-ADAccount -Group "Administrators" -Member $DomainUser
        }
    }
}
function Import-GPO{
    Foreach ($gpoitem in Get-ChildItem ".\GPOs") {
        Write-Output "Importing $gpoitem"
        .\LGPO.exe /g GPOs\$gpoitem
    }
    gpupdate /force
}
function Import-Secpol {
    Write-Output "Importing secpol.inf"
    $dir ='.\secpol.inf'
    secedit.exe /configure /db C:\Windows\security\local.sdb /cfg $dir
}
function Set-Services ([Boolean]$KeepRD){
    if($KeepRD){
        "TermService" | Write-Output -FilePath "enabled_services.txt"
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
    }
    $EnabledServices = Get-Content -Path "enabled_services.txt"
    $DisabledServices = Get-Content -Path "disabled_services.txt"

    foreach($Service in $EnabledServices) {
        Write-Output "Starting $Service"
        Set-Service $Service -StartupType Automatic
        Start-Service $Service
    }
    foreach($Service in $DisabledServices) {
        Write-Output "Stopping $Service"
        Set-Service $Service -StartupType Disabled
        Stop-Service $Service
    }
}
function Set-Features {
    Disable-PSRemoting -Force
    Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient
    Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
}
function Set-Browser-Settings {
    # should eventually include chrome, edge, internet explorer, firefox and some form of parameter to toggle each of these
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
function Enable-WindowsDefender {
    Write-Output "Enabling and configuring Windows Defender"
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
    if($null -ne (Get-MpPreference | Select-Object -Property ExclusionPath -ExpandProperty ExclusionPath)) {
        Remove-MpPreference -ExclusionPath ( Get-MpPreference | Select-Object -Property ExclusionPath -ExpandProperty ExclusionPath)
    }    
}
function Invoke-MiscellaneousHardening {
    net share C:\ /delete
    bcdedit /set {current} nx AlwaysOn

    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v EnableFirewall /t REG_DWORD /d 1 /f # enable firewall
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
function Invoke-SMBHardening {
    Write-Output "Hardening the SMB service"
    
    Set-SmbServerConfiguration -EnableSMB2Protocol $true
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableBandwidthThrottling" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileInfoCacheEntriesMax" -Type "DWORD" -Value 1024 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DirectoryCacheEntriesMax" -Type "DWORD" -Value 1024 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileNotFoundCacheEntriesMax" -Type "DWORD" -Value 2048 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type "DWORD" -Value 20 -Force
    Set-SmbServerConfiguration -EnableMultiChannel $true -Force 
    Set-SmbServerConfiguration -MaxChannelPerSession 16 -Force
    Set-SmbServerConfiguration -ServerHidden $False -AnnounceServer $False -Force
    Set-SmbServerConfiguration -EnableLeasing $false -Force
    Set-SmbClientConfiguration -EnableLargeMtu $true -Force
    Set-SmbClientConfiguration -EnableMultiChannel $true -Force
    
    Write-Output "SMB Hardening"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "RestrictAnonymousSAM" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" -Value 256 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RestrictAnonymous" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Type "DWORD" -Value 1 -Force
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart
    Set-SmbClientConfiguration -RequireSecuritySignature $True -Force
    Set-SmbClientConfiguration -EnableSecuritySignature $True -Force
    Set-SmbServerConfiguration -EncryptData $True -Force 
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 
}
# functions end ---

Start-Transcript -Append log.txt
Write-Output "|| ccs.ps1 started ||"

# main
Enable-Firewall
Enable-WindowsDefender

$SecurePassword = ConvertTo-SecureString -String 'CyberPatriot123!@#' -AsPlainText -Force
Set-LocalUsers -Password $SecurePassword
#Set-ADUsers -Password $SecurePassword

#Import-GPO
Import-Secpol
Set-AuditPolicy
Set-UAC
Set-Services -keepRD $false
Set-Features
#Set-Browser-Settings

# service hardening
#Invoke-SMBHardening

# main ends
Write-Output "|| ccs.ps1 finished ||"
Stop-Transcript
Invoke-Item ".\log.txt"