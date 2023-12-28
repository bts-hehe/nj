Write-Output "Finding files with alternate data streams, may take a while"
get-ChildItem -recurse | % { get-item $_.FullName -stream * } | where stream -ne ':$Data' | select filename,stream,@{'name'='identifier';"e"={"$($_.filename):$($_.stream)"}}

# https://jpsoft.com/forums/threads/finding-files-with-alternate-data-streams.9741/