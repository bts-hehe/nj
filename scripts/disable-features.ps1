Write-Output "`n---Disabling Insecure Windows Features"
Disable-PSRemoting -Force
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient
Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol