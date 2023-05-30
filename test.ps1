$users = Get-ChildItem "C:\Users"
foreach($user in $users) {
    write-output $user
}