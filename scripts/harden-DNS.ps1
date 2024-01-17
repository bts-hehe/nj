Write-Output "`n---Hardening the DNS service"
Set-DnsServerGlobalQueryBlockList -Enable $true