echo "|| starting script ||"

netsh advfirewall set allprofiles state on

:: users
set password="CyberPatriot123!@#"
for /F "tokens=*" %%user in (C:\temp\users.txt) do (
  :: net user /domain %%user %password%
  :: net user /domain %%user /ACTIVE NO
  echo %%user
)

echo "|| finishing script ||"