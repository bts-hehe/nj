# a lot of registry keys in case secpol.msc doesn't work -> see secpol.msc and aperture windows vulns
reg add HKLM\SYSTEM\CurrentControlSet\control\CrashControl /t REG_DWORD /v CrashDumpEnabled /d 0
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168 /t REG_DWORD /v Enabled /d 0
