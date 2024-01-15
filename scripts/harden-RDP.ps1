Write-Output "`n---Hardening the RDP service"

# enable NLA
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
# To set Minimum Encryption Level to "High" instead of "Client Compatible"
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel /t REG_DWORD /d 3 /f
# To set Security Layer to "SSL (TLS 1.0)" instead of "Negotiate" - https://serverfault.com/questions/83884/require-tls-on-rdp-for-all-connections
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 3 /f
