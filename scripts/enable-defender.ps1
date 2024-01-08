Write-Output "`n---Enabling and configuring Windows Defender"

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f # stig V-213428
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d 1 /f # stig V-213426

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v EnableNetworkProtection /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d 0 /f # V-213451 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScriptScanning" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideRealtimeScanDirection" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableIOAVProtection" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 0 /f # V-213433 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleDay" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "5" /t REG_SZ /d 2 /f

# ASR rules 
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "3B576869-A4EC-4529-8536-B80A7769E899" /t REG_SZ /d 1 /f # V-213458	- block office apps from creating executable content
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" /t REG_SZ /d 1 /f # V-213459	- block office applications from injecting into other processes
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" /t REG_SZ /d 1 /f # block executable content from email client and webmail 
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" /t REG_SZ /d 1 /f # block Office applications from creating child processes. 
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" /t REG_SZ /d 1 /f # Block Adobe Reader from creating child processes
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' /t REG_SZ /d 1 /f # Block credential stealing from the Windows local security authority subsystem (lsass.exe) 
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '01443614-cd74-433a-b99e-2ecdc07bfc25' /t REG_SZ /d 1 /f # Block executable files from running unless they meet a prevalence, age, or trusted list criteria 
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' /t REG_SZ /d 1 /f # Block execution of potentially obfuscated scripts 
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'D3E037E1-3EB8-44C8-A917-57927947596D' /t REG_SZ /d 1 /f # Block JavaScript or VBScript from launching downloaded executable content 
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '26190899-1602-49e8-8b27-eb1d0a1ce869' /t REG_SZ /d 1 /f # Block Office communication applications from creating child processes 
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'e6db77e5-3df2-4cf1-b95a-636979351e5b' /t REG_SZ /d 1 /f # Block persistence through WMI event subscription 
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'd1e49aac-8f56-4280-b9ba-993a6d77406c' /t REG_SZ /d 1 /f # Block process creations originating from PSExec and WMI commands 
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' /t REG_SZ /d 1 /f # Block untrusted and unsigned processes that run from USB 
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' /t REG_SZ /d 1 /f # Block Win32 API calls from Office macro 
reg add 'HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' /v 'c1db55ab-c21a-4637-bb3f-a12568109d35' /t REG_SZ /d 1 /f # Use advanced protection against ransomware 

Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -AllowNetworkProtectionOnWinServer $true
Set-MpPreference -DisableNetworkProtectionPerfTelemetry $true
Set-MPPreference -DisableBehaviorMonitoring $false
Set-MPPreference -DisableIntrusionPreventionSystem $false
Set-MPPreference -DisableIOAVProtection $false
Set-MPPreference -DisableEmailScanning $false
Set-MPPreference -DisableScriptScanning $false
Set-MPPreference -DisableRealtimeMonitoring $false
Set-MPPreference -DisableTamperProtection $false



if($null -ne (Get-MpPreference | Select-Object -Property ExclusionPath -ExpandProperty ExclusionPath)) {
    Write-Output "Removing all Defender Exclusions: "
    Write-Output (Get-MpPreference | Select-Object -Property ExclusionPath -ExpandProperty ExclusionPath)
    Remove-MpPreference -ExclusionPath ( Get-MpPreference | Select-Object -Property ExclusionPath -ExpandProperty ExclusionPath)
}else{
    Write-Output "Did not find any Defender Exclusions to remove."
}