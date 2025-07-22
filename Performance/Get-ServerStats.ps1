#   Get-ServerStats.ps1
# Author      - Jason Gebhart (Updated)  
# Script Name - Get-ServerStats.ps1
<#
.SYNOPSIS 
    Gets comprehensive server performance statistics and health metrics.

.DESCRIPTION
    This script collects detailed server performance metrics including CPU, memory, disk,
    network utilization, and system health indicators. Designed for VDI and server 
    infrastructure monitoring with configurable thresholds for alerting.

.PARAMETER ComputerName
    Specifies the name of one or more computers to query. Default is the local computer.

.PARAMETER IncludeProcesses
    Include top CPU/Memory consuming processes in the output. Default is true.

.PARAMETER ProcessCount
    Number of top processes to include when IncludeProcesses is true. Default is 5.

.PARAMETER IncludeServices
    Include critical service status in the output. Default is true.

.PARAMETER IncludeDiskDetails
    Include detailed disk space and performance metrics. Default is true.

.PARAMETER SampleInterval
    Number of seconds to sample performance counters. Default is 2 seconds.

.EXAMPLE
    .\Get-ServerStats.ps1
    Gets comprehensive server statistics for the local computer.

.EXAMPLE
    .\Get-ServerStats.ps1 -ComputerName "SERVER01" -ProcessCount 10
    Gets server stats for SERVER01 including top 10 processes.

.EXAMPLE
    .\Get-ServerStats.ps1 -ComputerName @("VDI01","VDI02") -SampleInterval 5
    Gets server stats for multiple VDI servers with 5-second sampling.
#>

[CmdletBinding()]
param (
    [Parameter(Position=0, Mandatory=$false, ValueFromPipeline = $true)]
    [string[]]$ComputerName = @("$env:COMPUTERNAME"),
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeProcesses = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$ProcessCount = 5,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeServices = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeDiskDetails = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$SampleInterval = 2
)

# Define performance thresholds
$thresholds = @{
    CPUWarning = 80
    CPUCritical = 95
    MemoryWarning = 85
    MemoryCritical = 95
    DiskWarning = 85
    DiskCritical = 95
    DiskQueueWarning = 2
    DiskQueueCritical = 5
}

# Critical services to monitor
$criticalServices = @(
    "Spooler", "DHCP", "DNS", "EventLog", "LanmanServer", "LanmanWorkstation",
    "RemoteRegistry", "RpcSs", "Schedule", "W32Time", "WinRM", "Winlogon"
)

function Get-PerformanceCounters {
    param(
        [string]$Computer,
        [int]$Interval
    )
    
    try {
        Write-Verbose "Collecting performance counters for $Computer"
        
        # Get multiple samples for accurate CPU measurement
        $counters = @(
            "\Processor(_Total)\% Processor Time",
            "\Memory\Available MBytes", 
            "\Memory\Committed Bytes",
            "\System\Processor Queue Length",
            "\PhysicalDisk(_Total)\Avg. Disk Queue Length",
            "\PhysicalDisk(_Total)\% Disk Time",
            "\Network Interface(*)\Bytes Total/sec"
        )
        
        if ($Computer -eq $env:COMPUTERNAME) {
            # Local execution - get multiple samples
            $sample1 = Get-Counter -Counter $counters -ErrorAction SilentlyContinue
            Start-Sleep -Seconds $Interval
            $sample2 = Get-Counter -Counter $counters -ErrorAction SilentlyContinue
            
            $samples = @($sample1, $sample2)
        } else {
            # Remote execution
            $samples = Invoke-Command -ComputerName $Computer -ScriptBlock {
                param($counterList, $interval)
                
                $sample1 = Get-Counter -Counter $counterList -ErrorAction SilentlyContinue
                Start-Sleep -Seconds $interval
                $sample2 = Get-Counter -Counter $counterList -ErrorAction SilentlyContinue
                
                return @($sample1, $sample2)
            } -ArgumentList $counters, $Interval -ErrorAction SilentlyContinue
        }
        
        if (-not $samples -or $samples.Count -eq 0) {
            throw "No performance counter data available"
        }
        
        # Calculate averages from samples
        $perfData = @{}
        foreach ($counter in $counters) {
            $values = @()
            foreach ($sample in $samples) {
                if ($sample -and $sample.CounterSamples) {
                    $counterSample = $sample.CounterSamples | Where-Object { $_.Path -like "*$($counter.Split('\')[-1])" }
                    if ($counterSample) {
                        $values += $counterSample.CookedValue
                    }
                }
            }
            if ($values.Count -gt 0) {
                $perfData[$counter] = ($values | Measure-Object -Average).Average
            }
        }
        
        return $perfData
        
    } catch {
        Write-Warning "Error collecting performance counters for $Computer`: $($_.Exception.Message)"
        return @{}
    }
}

function Get-SystemInfo {
    param([string]$Computer)
    
    try {
        if ($Computer -eq $env:COMPUTERNAME) {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem
            $os = Get-CimInstance -ClassName Win32_OperatingSystem  
            $proc = Get-CimInstance -ClassName Win32_Processor
        } else {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $Computer
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer
            $proc = Get-CimInstance -ClassName Win32_Processor -ComputerName $Computer
        }
        
        return @{
            ComputerSystem = $cs
            OperatingSystem = $os
            Processor = $proc
        }
    } catch {
        Write-Warning "Error getting system info for $Computer`: $($_.Exception.Message)"
        return $null
    }
}

# Main processing
$allResults = @()

foreach ($computer in $ComputerName) {
    try {
        Write-Verbose "Processing server: $computer"
        
        # Get system information
        $sysInfo = Get-SystemInfo -Computer $computer
        if (-not $sysInfo) {
            $allResults += [PSCustomObject]@{
                Computer = $computer
                Status = "Error"
                Message = "Unable to connect or retrieve system information"
                Timestamp = Get-Date
            }
            continue
        }
        
        # Get performance counters
        $perfData = Get-PerformanceCounters -Computer $computer -Interval $SampleInterval
        
        # Calculate key metrics
        $totalRAM = [math]::Round($sysInfo.OperatingSystem.TotalVisibleMemorySize / 1MB, 2)
        $availableRAM = if ($perfData["\Memory\Available MBytes"]) { 
            [math]::Round($perfData["\Memory\Available MBytes"], 2) 
        } else { 0 }
        $memoryUsedPercent = if ($totalRAM -gt 0) { 
            [math]::Round(((($totalRAM * 1024) - $availableRAM) / ($totalRAM * 1024)) * 100, 2) 
        } else { 0 }
        
        $cpuUsage = if ($perfData["\Processor(_Total)\% Processor Time"]) { 
            [math]::Round($perfData["\Processor(_Total)\% Processor Time"], 2) 
        } else { 0 }
        
        # Determine health status
        $healthStatus = "Healthy"
        $alerts = @()
        
        if ($cpuUsage -ge $thresholds.CPUCritical) {
            $healthStatus = "Critical"
            $alerts += "CPU usage critical ($cpuUsage%)"
        } elseif ($cpuUsage -ge $thresholds.CPUWarning) {
            $healthStatus = "Warning"
            $alerts += "CPU usage high ($cpuUsage%)"
        }
        
        if ($memoryUsedPercent -ge $thresholds.MemoryCritical) {
            $healthStatus = "Critical"  
            $alerts += "Memory usage critical ($memoryUsedPercent%)"
        } elseif ($memoryUsedPercent -ge $thresholds.MemoryWarning) {
            if ($healthStatus -ne "Critical") { $healthStatus = "Warning" }
            $alerts += "Memory usage high ($memoryUsedPercent%)"
        }
        
        # Get top processes if requested
        $topProcesses = @()
        if ($IncludeProcesses) {
            try {
                if ($computer -eq $env:COMPUTERNAME) {
                    $processes = Get-Process | Sort-Object CPU -Descending | Select-Object -First $ProcessCount
                } else {
                    $processes = Invoke-Command -ComputerName $computer -ScriptBlock {
                        param($count)
                        Get-Process | Sort-Object CPU -Descending | Select-Object -First $count Name, CPU, WorkingSet, Id
                    } -ArgumentList $ProcessCount -ErrorAction SilentlyContinue
                }
                
                $topProcesses = $processes | ForEach-Object {
                    [PSCustomObject]@{
                        Name = $_.Name
                        CPU = if ($_.CPU) { [math]::Round($_.CPU, 2) } else { 0 }
                        MemoryMB = if ($_.WorkingSet) { [math]::Round($_.WorkingSet / 1MB, 2) } else { 0 }
                        ProcessId = $_.Id
                    }
                }
            } catch {
                Write-Warning "Error getting process information for $computer"
            }
        }
        
        # Get critical service status if requested
        $serviceStatus = @()
        if ($IncludeServices) {
            try {
                if ($computer -eq $env:COMPUTERNAME) {
                    $services = Get-Service -Name $criticalServices -ErrorAction SilentlyContinue
                } else {
                    $services = Get-Service -Name $criticalServices -ComputerName $computer -ErrorAction SilentlyContinue
                }
                
                $serviceStatus = $services | ForEach-Object {
                    if ($_.Status -ne "Running") {
                        if ($healthStatus -eq "Healthy") { $healthStatus = "Warning" }
                        $alerts += "Service '$($_.Name)' is $($_.Status)"
                    }
                    
                    [PSCustomObject]@{
                        Name = $_.Name
                        Status = $_.Status
                        StartType = $_.StartType
                    }
                }
            } catch {
                Write-Warning "Error getting service information for $computer"
            }
        }
        
        # Get disk information if requested
        $diskInfo = @()
        if ($IncludeDiskDetails) {
            try {
                if ($computer -eq $env:COMPUTERNAME) {
                    $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
                } else {
                    $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $computer
                }
                
                $diskInfo = $disks | ForEach-Object {
                    $freePercent = [math]::Round(($_.FreeSpace / $_.Size) * 100, 2)
                    $usedPercent = 100 - $freePercent
                    
                    if ($usedPercent -ge $thresholds.DiskCritical) {
                        $healthStatus = "Critical"
                        $alerts += "Disk $($_.DeviceID) usage critical ($usedPercent%)"
                    } elseif ($usedPercent -ge $thresholds.DiskWarning) {
                        if ($healthStatus -eq "Healthy") { $healthStatus = "Warning" }
                        $alerts += "Disk $($_.DeviceID) usage high ($usedPercent%)"
                    }
                    
                    [PSCustomObject]@{
                        Drive = $_.DeviceID
                        SizeGB = [math]::Round($_.Size / 1GB, 2)
                        FreeGB = [math]::Round($_.FreeSpace / 1GB, 2)
                        UsedPercent = $usedPercent
                        Label = $_.VolumeName
                    }
                }
            } catch {
                Write-Warning "Error getting disk information for $computer"
            }
        }
        
        # Create comprehensive result object
        $result = [PSCustomObject]@{
            Computer = $computer
            Status = $healthStatus
            Timestamp = Get-Date
            
            # System Information
            OSName = $sysInfo.OperatingSystem.Caption
            OSVersion = $sysInfo.OperatingSystem.Version
            LastBootTime = $sysInfo.OperatingSystem.LastBootUpTime
            SystemModel = $sysInfo.ComputerSystem.Model
            SystemManufacturer = $sysInfo.ComputerSystem.Manufacturer
            
            # Performance Metrics
            CPUUsagePercent = $cpuUsage
            MemoryTotalGB = $totalRAM
            MemoryAvailableGB = $availableRAM
            MemoryUsedPercent = $memoryUsedPercent
            ProcessorCount = $sysInfo.Processor.Count
            LogicalProcessors = $sysInfo.ComputerSystem.NumberOfLogicalProcessors
            
            # Additional Performance Data
            ProcessorQueueLength = if ($perfData["\System\Processor Queue Length"]) { 
                [math]::Round($perfData["\System\Processor Queue Length"], 2) 
            } else { 0 }
            DiskQueueLength = if ($perfData["\PhysicalDisk(_Total)\Avg. Disk Queue Length"]) { 
                [math]::Round($perfData["\PhysicalDisk(_Total)\Avg. Disk Queue Length"], 2) 
            } else { 0 }
            DiskUsagePercent = if ($perfData["\PhysicalDisk(_Total)\% Disk Time"]) { 
                [math]::Round($perfData["\PhysicalDisk(_Total)\% Disk Time"], 2) 
            } else { 0 }
            
            # Health and Alerting
            Alerts = $alerts -join "; "
            AlertCount = $alerts.Count
            
            # Detailed Information (if requested)
            TopProcesses = $topProcesses
            CriticalServices = $serviceStatus  
            DiskDetails = $diskInfo
            
            # Uptime calculation
            UptimeDays = if ($sysInfo.OperatingSystem.LastBootUpTime -and $sysInfo.OperatingSystem.LastBootUpTime -ne "-") {
                try {
                    [math]::Round((Get-Date - [datetime]$sysInfo.OperatingSystem.LastBootUpTime).TotalDays, 2)
                } catch {
                    0
                }
            } else { 0 }
        }
        
        $allResults += $result
        Write-Verbose "Completed processing for $computer - Status: $healthStatus"
        
    } catch {
        Write-Error "Error processing server stats for $computer`: $($_.Exception.Message)"
        
        $allResults += [PSCustomObject]@{
            Computer = $computer
            Status = "Error"
            Message = "Critical error during stats collection: $($_.Exception.Message)"
            Timestamp = Get-Date
        }
    }
}

# Sort results by status (critical first) and then by computer name
$sortedResults = $allResults | Sort-Object @{
    Expression = {
        switch ($_.Status) {
            'Critical' { 1 }
            'Warning' { 2 }
            'Healthy' { 3 }
            'Error' { 4 }
            default { 5 }
        }
    }
}, Computer

Write-Verbose "Server stats collection completed for $($ComputerName.Count) computers"

return $sortedResults