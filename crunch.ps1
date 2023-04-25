# start firewall, fix it maybe
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Block –NotifyOnListen True
'''
asdfasdf
'''
New-NetFirewallRule -DisplayName “Allow Inbound Telnet” -Direction Inbound -Program %SystemRoot%\System32\tlntsvr.exe -RemoteAddress LocalSubnet -Action Allow


# disable/enable services
set-service eventlog -start a -status running
set-service snmptrap -start d -status stopped
set-service iphlpsvc -start d -status stopped

# passwords
Get-LocalUser | Set-LocalUser -Password (Read-Host -AsSecureString "local pass: ")
Get-ADUser | Set-ADUser -Password (Read-Host -AsSecureString "AD pass:")
