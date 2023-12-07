param (
    [Parameter(Mandatory)]
    [int] $ProductType
)
$sid = Get-LocalUser -Name $env:USERNAME | Select-Object SID | ForEach-Object{$_.SID.Value}

# a lot of registry keys in case secpol.msc doesn't work -> see secpol.msc and aperture windows vulns

# below came from clement chan's old script (anti-scorpio) 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers /v DisableAutoplay /t REG_DWORD /d 1 /f
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v UserAuthentication /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel /t REG_DWORD /d 3 /f
reg add HKLM\System\CurrentControlSet\Control\LSA /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScreenSaverGracePeriod /t REG_DWORD /d 0 /f



reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /t REG_DWORD /v CrashDumpEnabled /d 0 # KAC
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /t REG_DWORD /v Enabled /d 0 # KAC

# Include command line in process creation events
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d 1 /f

# Powershell command transcription
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\Windows\debug\timber" /f

# unhide hidden files in file explorer
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f

# enable Internet Explorer Enhanced Security Configuration
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v IEHarden /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v lEHardenlENoWarn /t REG_DWORD /d 1 /f


# for keys exclusive to servers
if (($ProductType -eq 2) -or ($ProductType -eq 3)) { # 2=DC, 3=server without AD
    reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f
}
