Write-Output "`n---Finding media files"
# Get-ChildItem -path C:\ -filter *.txt -file -ErrorAction silentlycontinue -recurse | Select-Object -Property Directory, Name | out-file "output.txt"


# smth like that