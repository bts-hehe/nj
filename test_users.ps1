$users = Get-ChildItem "C:\Users"
foreach($user in $users) {
    write-output "idk"+$user
}
