$tasks = Get-ScheduledTask | Select-Object -ExpandProperty TaskName 
$srvTasks = Get-Content -Path "$PSScriptRoot/../tasks.txt" #replace with relative path name 
foreach($task in $tasks){
    if ($srvTasks -notcontains $task){ # if user doesn't exist
        Add-Content -Path "$PSScriptRoot/../extraTasks.txt" $task #replace with relative path 
	
    } 
}