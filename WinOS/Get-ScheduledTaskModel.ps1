#   Get-ScheduledTaskModel.ps1
# Author      - Jason Gebhart (Updated)
# Script Name - Get-ScheduledTaskModel.ps1
<#
.SYNOPSIS 
    Gets comprehensive scheduled task information for system monitoring.

.DESCRIPTION
    This script retrieves detailed information about scheduled tasks on the local or remote computer,
    including task status, last run time, next run time, and configuration details. It focuses on
    critical system tasks and can identify potentially problematic or suspicious tasks.

.PARAMETER ComputerName
    Specifies the name of one or more computers to query. Default is the local computer.

.PARAMETER IncludeDisabled
    Include disabled tasks in the output. Default is false.

.PARAMETER TaskPath
    Filter tasks by path pattern (e.g., "\Microsoft\Windows\*"). Default is all paths.

.PARAMETER CriticalOnly
    Only return tasks that are marked as critical or important. Default is false.

.EXAMPLE
    .\Get-ScheduledTaskModel.ps1
    Returns scheduled task information for the local computer.

.EXAMPLE
    .\Get-ScheduledTaskModel.ps1 -ComputerName "SERVER01" -IncludeDisabled
    Returns all scheduled tasks including disabled ones for SERVER01.

.EXAMPLE
    .\Get-ScheduledTaskModel.ps1 -TaskPath "\Microsoft\Windows\UpdateOrchestrator\*"
    Returns only Windows Update related tasks.
#>

[CmdletBinding()]
param (
    [Parameter(Position=0, Mandatory=$false, ValueFromPipeline = $true)]
    [string]$ComputerName = "$env:COMPUTERNAME",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabled,
    
    [Parameter(Mandatory=$false)]
    [string]$TaskPath = "*",
    
    [Parameter(Mandatory=$false)]
    [switch]$CriticalOnly
)

try {
    Write-Verbose "Getting scheduled tasks for computer: $ComputerName"
    
    # Get all scheduled tasks
    if ($ComputerName -eq $env:COMPUTERNAME) {
        # Local execution
        $tasks = Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue
    } else {
        # Remote execution
        $tasks = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($path)
            Get-ScheduledTask -TaskPath $path -ErrorAction SilentlyContinue
        } -ArgumentList $TaskPath -ErrorAction SilentlyContinue
    }
    
    if (-not $tasks) {
        Write-Warning "No scheduled tasks found or unable to access scheduled tasks"
        return @()
    }
    
    $results = @()
    
    foreach ($task in $tasks) {
        try {
            # Skip disabled tasks unless requested
            if (-not $IncludeDisabled -and $task.State -eq 'Disabled') {
                continue
            }
            
            # Get task info including last run details
            $taskInfo = if ($ComputerName -eq $env:COMPUTERNAME) {
                Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            } else {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    param($taskName, $taskPath)
                    Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
                } -ArgumentList $task.TaskName, $task.TaskPath -ErrorAction SilentlyContinue
            }
            
            # Determine if task is critical
            $isCritical = $false
            $criticalPaths = @(
                "*UpdateOrchestrator*", "*WindowsUpdate*", "*Antimalware*", "*Defender*", 
                "*Backup*", "*SystemRestore*", "*DiskCleanup*", "*Defrag*", 
                "*MemoryDiagnostic*", "*ErrorReporting*", "*Recovery*"
            )
            
            foreach ($criticalPath in $criticalPaths) {
                if ($task.TaskPath -like $criticalPath -or $task.TaskName -like $criticalPath) {
                    $isCritical = $true
                    break
                }
            }
            
            # Skip non-critical tasks if CriticalOnly is specified
            if ($CriticalOnly -and -not $isCritical) {
                continue
            }
            
            # Determine task health status
            $healthStatus = switch ($task.State) {
                'Ready' { 
                    if ($taskInfo -and $taskInfo.LastTaskResult -eq 0) { 'Healthy' }
                    elseif ($taskInfo -and $taskInfo.LastTaskResult -ne 0 -and $taskInfo.LastTaskResult -ne 267009) { 'Warning' }
                    else { 'Ready' }
                }
                'Running' { 'Running' }
                'Disabled' { 'Disabled' }
                default { 'Unknown' }
            }
            
            # Create result object
            $result = [PSCustomObject]@{
                Computer = $ComputerName
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = $task.State
                Author = $task.Author
                Description = if ($task.Description) { $task.Description } else { "No description" }
                LastRunTime = if ($taskInfo) { $taskInfo.LastRunTime } else { "Never" }
                LastTaskResult = if ($taskInfo) { $taskInfo.LastTaskResult } else { "Unknown" }
                NextRunTime = if ($taskInfo) { $taskInfo.NextRunTime } else { "Not scheduled" }
                NumberOfMissedRuns = if ($taskInfo) { $taskInfo.NumberOfMissedRuns } else { 0 }
                HealthStatus = $healthStatus
                IsCritical = $isCritical
                URI = $task.URI
                SecurityDescriptor = $task.SecurityDescriptor
                Triggers = if ($task.Triggers) { 
                    ($task.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join "; " 
                } else { "None" }
                Actions = if ($task.Actions) { 
                    ($task.Actions | ForEach-Object { 
                        if ($_.Execute) { $_.Execute } 
                        elseif ($_.Id) { $_.Id }
                        else { $_.CimClass.CimClassName }
                    }) -join "; " 
                } else { "None" }
            }
            
            $results += $result
            
        } catch {
            Write-Warning "Error processing task '$($task.TaskName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Sort results by health status (problems first) and then by name
    $sortedResults = $results | Sort-Object @{
        Expression = {
            switch ($_.HealthStatus) {
                'Warning' { 1 }
                'Unknown' { 2 }
                'Running' { 3 }
                'Ready' { 4 }
                'Healthy' { 5 }
                'Disabled' { 6 }
                default { 7 }
            }
        }
    }, TaskName
    
    Write-Verbose "Found $($sortedResults.Count) scheduled tasks matching criteria"
    
    return $sortedResults
    
} catch {
    Write-Error "Error retrieving scheduled tasks: $($_.Exception.Message)"
    
    # Return error object
    return [PSCustomObject]@{
        Computer = $ComputerName
        TaskName = "ERROR"
        TaskPath = "/"
        State = "Error"
        Author = "System"
        Description = "Failed to retrieve scheduled tasks: $($_.Exception.Message)"
        LastRunTime = Get-Date
        LastTaskResult = -1
        NextRunTime = "Unknown"
        NumberOfMissedRuns = 0
        HealthStatus = "Error"
        IsCritical = $false
        URI = ""
        SecurityDescriptor = ""
        Triggers = ""
        Actions = ""
    }
}