reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services

# smth here idk yet
Get-Service | Select-Object -ExpandProperty Name