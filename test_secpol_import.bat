$dir ='C:\win-main\secpol.inf'
secedit.exe /configure /db %windir%\security\local.sdb /cfg $dir


:: to do is to test this