# start firewall, fix it maybe
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Block

# firewall rules
Disable-NetFirewallRule -All
New-NetFirewallRule -DisplayName “local in” -Direction Inbound -RemoteAddress LocalSubnet -Action Allow # don't know if these 2 rules work
New-NetFirewallRule -DisplayName “local out" -Direction Outbound -RemoteAddress LocalSubnet -Action Allow

$ServicePorts = Read-Host "Hosted checked service ports:"
New-NetFirewallRule -DisplayName “service in” -Direction Inbound -LocalPort $ServicePorts -Action Allow 

# disable guest/Administrator accounts
Disable-LocalUser -Name "Administrator"
Disable-LocalUser -Name "Guest"

Disable-ADAccount -Name "Administrator"
Disable-ADAccount -Name "Guest"

# disable/enable services
set-service eventlog -start a -status running
set-service snmptrap -start d -status stopped
set-service iphlpsvc -start d -status stopped

# passwords
Get-LocalUser | Set-LocalUser -Password (Read-Host -AsSecureString "local pass: ")
Get-ADUser | Set-ADUser -Password (Read-Host -AsSecureString "AD pass:")
