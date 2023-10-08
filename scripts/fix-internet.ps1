Write-Output "`n---Configuring Internet"
<#
todo
- check network adapters
- check firewall rules?
#>
#Disable IPv6 Services --> Does not disable IPv6 interface
netsh interface teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled