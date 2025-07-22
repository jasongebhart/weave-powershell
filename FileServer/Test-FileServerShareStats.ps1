#   Test-FileServerShareStats.ps1
# Author      - Jason Gebhart (Updated)
# Script Name - Test-FileServerShareStats.ps1
<#
.SYNOPSIS 
    Gets comprehensive file server share statistics and usage analysis.

.DESCRIPTION
    This script analyzes file server shares to provide detailed statistics including
    share usage, file counts, folder sizes, access patterns, and potential issues.
    Useful for capacity planning, performance optimization, and compliance monitoring.

.PARAMETER ComputerName
    Specifies the name of the file server to analyze. Default is the local computer.

.PARAMETER ShareNames
    Array of share names to analyze. If not specified, will analyze all non-admin shares.

.PARAMETER IncludeHidden
    Include hidden shares in the analysis. Default is false.

.PARAMETER MaxDepth
    Maximum folder depth to analyze for detailed statistics. Default is 2 levels.

.PARAMETER SizeThresholdMB
    Report folders larger than this threshold in MB. Default is 100MB.

.EXAMPLE
    .\Test-FileServerShareStats.ps1
    Analyzes all shares on the local computer.

.EXAMPLE
    .\Test-FileServerShareStats.ps1 -ComputerName "FILESERVER01" -ShareNames @("Data", "Home")
    Analyzes specific shares on a remote file server.

.EXAMPLE
    .\Test-FileServerShareStats.ps1 -MaxDepth 3 -SizeThresholdMB 500 -IncludeHidden
    Performs deep analysis including hidden shares with custom thresholds.
#>

[CmdletBinding()]
param (
    [Parameter(Position=0, Mandatory=$false, ValueFromPipeline = $true)]
    [string]$ComputerName = "$env:COMPUTERNAME",
    
    [Parameter(Mandatory=$false)]
    [string[]]$ShareNames = @(),
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeHidden = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxDepth = 2,
    
    [Parameter(Mandatory=$false)]
    [int]$SizeThresholdMB = 100
)

function Get-FolderSizeInfo {
    param(
        [string]$Path,
        [int]$MaxDepth,
        [int]$CurrentDepth = 0
    )
    
    $result = @{
        Path = $Path
        SizeMB = 0
        FileCount = 0
        FolderCount = 0
        LargestFile = ""
        LargestFileSizeMB = 0
        OldestFile = ""
        NewestFile = ""
        Subfolders = @()
    }
    
    try {
        if (-not (Test-Path $Path)) {
            return $result
        }
        
        # Get all items in current directory
        $items = Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue
        
        if ($items) {
            $files = $items | Where-Object { -not $_.PSIsContainer }
            $folders = $items | Where-Object { $_.PSIsContainer }
            
            $result.FileCount = $files.Count
            $result.FolderCount = $folders.Count
            
            # Calculate size and find largest file
            foreach ($file in $files) {
                $fileSizeMB = [math]::Round($file.Length / 1MB, 2)
                $result.SizeMB += $fileSizeMB
                
                if ($fileSizeMB -gt $result.LargestFileSizeMB) {
                    $result.LargestFileSizeMB = $fileSizeMB
                    $result.LargestFile = $file.Name
                }
            }
            
            # Find oldest and newest files
            if ($files.Count -gt 0) {
                $oldestFile = $files | Sort-Object LastWriteTime | Select-Object -First 1
                $newestFile = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                
                $result.OldestFile = "$($oldestFile.Name) ($($oldestFile.LastWriteTime))"
                $result.NewestFile = "$($newestFile.Name) ($($newestFile.LastWriteTime))"
            }
            
            # Recurse into subfolders if within depth limit
            if ($CurrentDepth -lt $MaxDepth) {
                foreach ($folder in $folders) {
                    $subfolderInfo = Get-FolderSizeInfo -Path $folder.FullName -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
                    
                    $result.SizeMB += $subfolderInfo.SizeMB
                    $result.FileCount += $subfolderInfo.FileCount
                    $result.FolderCount += $subfolderInfo.FolderCount
                    
                    if ($subfolderInfo.SizeMB -gt 0) {
                        $result.Subfolders += [PSCustomObject]@{
                            Name = $folder.Name
                            SizeMB = $subfolderInfo.SizeMB
                            FileCount = $subfolderInfo.FileCount
                            FolderCount = $subfolderInfo.FolderCount
                        }
                    }
                }
            }
        }
        
        $result.SizeMB = [math]::Round($result.SizeMB, 2)
        
    } catch {
        Write-Warning "Error analyzing folder '$Path': $($_.Exception.Message)"
    }
    
    return $result
}

try {
    Write-Verbose "Starting file server share analysis for: $ComputerName"
    
    $results = @()
    $totalShares = 0
    $totalSizeMB = 0
    $totalFiles = 0
    
    # Get shares to analyze
    Write-Verbose "Getting SMB shares for analysis"
    
    if ($ComputerName -eq $env:COMPUTERNAME) {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
    } else {
        $shares = Get-SmbShare -CimSession $ComputerName -ErrorAction SilentlyContinue
    }
    
    if (-not $shares) {
        Write-Warning "No SMB shares found or unable to access shares on $ComputerName"
        return @()
    }
    
    # Filter shares based on parameters
    $filteredShares = $shares | Where-Object {
        # Include only file system directories
        $_.ShareType -eq 'FileSystemDirectory' -and
        
        # Include/exclude hidden shares
        ($IncludeHidden -or -not $_.Name.EndsWith('$')) -and
        
        # Filter by specific share names if provided
        ($ShareNames.Count -eq 0 -or $ShareNames -contains $_.Name)
    }
    
    Write-Verbose "Analyzing $($filteredShares.Count) shares"
    $totalShares = $filteredShares.Count
    
    foreach ($share in $filteredShares) {
        try {
            Write-Verbose "Analyzing share: $($share.Name)"
            
            $sharePath = $share.Path
            if (-not $sharePath) {
                Write-Warning "Share '$($share.Name)' has no valid path"
                continue
            }
            
            # Get share permissions
            $shareAccess = @()
            try {
                if ($ComputerName -eq $env:COMPUTERNAME) {
                    $sharePermissions = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                } else {
                    $sharePermissions = Get-SmbShareAccess -Name $share.Name -CimSession $ComputerName -ErrorAction SilentlyContinue
                }
                
                if ($sharePermissions) {
                    $shareAccess = $sharePermissions | ForEach-Object {
                        "$($_.AccountName):$($_.AccessRight):$($_.AccessControlType)"
                    }
                }
            } catch {
                Write-Warning "Unable to get share permissions for '$($share.Name)'"
            }
            
            # Analyze folder structure and size
            Write-Verbose "Calculating size and structure for share: $($share.Name)"
            
            $folderInfo = if ($ComputerName -eq $env:COMPUTERNAME) {
                Get-FolderSizeInfo -Path $sharePath -MaxDepth $MaxDepth
            } else {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    param($path, $maxDepth, $funcDef)
                    
                    # Recreate the function in the remote session
                    Invoke-Expression $funcDef
                    
                    return Get-FolderSizeInfo -Path $path -MaxDepth $maxDepth
                } -ArgumentList $sharePath, $MaxDepth, ${function:Get-FolderSizeInfo}.ToString() -ErrorAction SilentlyContinue
            }
            
            if (-not $folderInfo) {
                Write-Warning "Unable to analyze folder structure for share '$($share.Name)'"
                $folderInfo = @{
                    SizeMB = 0; FileCount = 0; FolderCount = 0
                    LargestFile = ""; LargestFileSizeMB = 0
                    OldestFile = ""; NewestFile = ""
                    Subfolders = @()
                }
            }
            
            # Identify large subfolders
            $largeSubfolders = $folderInfo.Subfolders | Where-Object { $_.SizeMB -ge $SizeThresholdMB } | 
                               Sort-Object SizeMB -Descending | Select-Object -First 10
            
            # Determine health status and recommendations
            $healthStatus = "Healthy"
            $recommendations = @()
            
            if ($folderInfo.SizeMB -eq 0) {
                $healthStatus = "Warning"
                $recommendations += "Share appears empty or inaccessible"
            } elseif ($folderInfo.SizeMB -gt 10000) {  # > 10GB
                $recommendations += "Large share - consider archiving old files"
            }
            
            if ($folderInfo.FileCount -gt 50000) {
                $healthStatus = "Warning"
                $recommendations += "High file count may impact performance"
            }
            
            if ($folderInfo.LargestFileSizeMB -gt 1000) {  # > 1GB
                $recommendations += "Very large files present - review if necessary"
            }
            
            # Check for potential issues
            $issues = @()
            if ($shareAccess -contains "*Everyone*") {
                $issues += "Share has 'Everyone' permissions"
                $healthStatus = "Warning"
            }
            
            if ($share.Name.EndsWith('$') -and $IncludeHidden) {
                $issues += "Administrative/Hidden share"
            }
            
            $totalSizeMB += $folderInfo.SizeMB
            $totalFiles += $folderInfo.FileCount
            
            # Create result object
            $result = [PSCustomObject]@{
                Computer = $ComputerName
                ShareName = $share.Name
                SharePath = $sharePath
                Description = $share.Description
                SizeMB = $folderInfo.SizeMB
                SizeGB = [math]::Round($folderInfo.SizeMB / 1024, 2)
                FileCount = $folderInfo.FileCount
                FolderCount = $folderInfo.FolderCount
                LargestFile = $folderInfo.LargestFile
                LargestFileSizeMB = $folderInfo.LargestFileSizeMB
                OldestFile = $folderInfo.OldestFile
                NewestFile = $folderInfo.NewestFile
                LargeSubfolders = ($largeSubfolders | ForEach-Object { "$($_.Name) ($($_.SizeMB)MB)" }) -join "; "
                SharePermissions = $shareAccess -join "; "
                HealthStatus = $healthStatus
                Issues = $issues -join "; "
                Recommendations = $recommendations -join "; "
                ShareType = $share.ShareType
                CachingMode = $share.CachingMode
                EncryptData = $share.EncryptData
                ContinuouslyAvailable = $share.ContinuouslyAvailable
                Timestamp = Get-Date
            }
            
            $results += $result
            
        } catch {
            Write-Warning "Error analyzing share '$($share.Name)': $($_.Exception.Message)"
            
            $results += [PSCustomObject]@{
                Computer = $ComputerName
                ShareName = $share.Name
                SharePath = "Error"
                Description = "Error during analysis"
                SizeMB = 0
                SizeGB = 0
                FileCount = 0
                FolderCount = 0
                LargestFile = ""
                LargestFileSizeMB = 0
                OldestFile = ""
                NewestFile = ""
                LargeSubfolders = ""
                SharePermissions = ""
                HealthStatus = "Error"
                Issues = "Analysis failed: $($_.Exception.Message)"
                Recommendations = "Review share configuration and permissions"
                ShareType = $share.ShareType
                CachingMode = ""
                EncryptData = $false
                ContinuouslyAvailable = $false
                Timestamp = Get-Date
            }
        }
    }
    
    # Add summary information
    $summary = [PSCustomObject]@{
        Computer = $ComputerName
        ShareName = "SUMMARY"
        SharePath = "Analysis Summary"
        Description = "File Server Share Analysis Summary"
        SizeMB = $totalSizeMB
        SizeGB = [math]::Round($totalSizeMB / 1024, 2)
        FileCount = $totalFiles
        FolderCount = 0
        LargestFile = ""
        LargestFileSizeMB = 0
        OldestFile = ""
        NewestFile = ""
        LargeSubfolders = ""
        SharePermissions = ""
        HealthStatus = if ($results | Where-Object { $_.HealthStatus -eq "Warning" -or $_.HealthStatus -eq "Error" }) { "Warning" } else { "Healthy" }
        Issues = "Shares analyzed: $totalShares"
        Recommendations = if ($totalSizeMB -gt 50000) { "Consider implementing data lifecycle management" } else { "File server usage appears normal" }
        ShareType = "Summary"
        CachingMode = ""
        EncryptData = $false
        ContinuouslyAvailable = $false
        Timestamp = Get-Date
    }
    
    # Sort results with summary first, then by size (largest first)
    $sortedResults = @($summary) + ($results | Sort-Object SizeMB -Descending)
    
    Write-Verbose "File server share analysis completed. Analyzed $totalShares shares totaling $totalSizeMB MB"
    
    return $sortedResults
    
} catch {
    Write-Error "Error during file server share analysis: $($_.Exception.Message)"
    
    return [PSCustomObject]@{
        Computer = $ComputerName
        ShareName = "ERROR"
        SharePath = "Critical Error"
        Description = "Critical error during share analysis"
        SizeMB = 0
        SizeGB = 0
        FileCount = 0
        FolderCount = 0
        LargestFile = ""
        LargestFileSizeMB = 0
        OldestFile = ""
        NewestFile = ""
        LargeSubfolders = ""
        SharePermissions = ""
        HealthStatus = "Error"
        Issues = "Critical error: $($_.Exception.Message)"
        Recommendations = "Check server connectivity and permissions"
        ShareType = "Error"
        CachingMode = ""
        EncryptData = $false
        ContinuouslyAvailable = $false
        Timestamp = Get-Date
    }
}