# start firewall, fix it maybe
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Block

# firewall rules
Disable-NetFirewallRule -All
New-NetFirewallRule -DisplayName “local in” -Direction Inbound -RemoteAddress LocalSubnet -Action Allow # don't know if these 2 rules work
New-NetFirewallRule -DisplayName “local out" -Direction Outbound -RemoteAddress LocalSubnet -Action Allow

$ServicePorts = Read-Host "Hosted checked service ports:"
New-NetFirewallRule -DisplayName “service in” -Direction Inbound -LocalPort $ServicePorts -Action Allow 