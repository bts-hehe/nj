Write-Output "Checking persistence methods"

$run = (reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run")
Write-Output $run
#https://tech-zealots.com/malware-analysis/malware-persistence-mechanisms/

# todo -> do a lot of reg queries