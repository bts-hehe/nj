echo "|| starting script ||"

netsh advfirewall set allprofiles state on

:: users
set password="CyberPatriot123!@#"
for /F "tokens=*" %%A in (C:\temp\users.txt) do (
  net user /domain %%A %password%
)

echo "|| finishing script ||"