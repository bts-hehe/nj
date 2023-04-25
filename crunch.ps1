# start firewall, fix it maybe
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Block –NotifyOnListen True

<#
multi-line comments look like this
#>
New-NetFirewallRule -DisplayName “loi” -Direction Inbound -RemoteAddress LocalSubnet -Action Allow # don't know if these 2 rules work
New-NetFirewallRule -DisplayName “loo" -Direction Outbound -RemoteAddress LocalSubnet -Action Allow

# disable/enable services
set-service eventlog -start a -status running
set-service snmptrap -start d -status stopped
set-service iphlpsvc -start d -status stopped

# passwords
Get-LocalUser | Set-LocalUser -Password (Read-Host -AsSecureString "local pass: ")
Get-ADUser | Set-ADUser -Password (Read-Host -AsSecureString "AD pass:")
