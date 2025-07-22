#   Test-FileServerACLModel.ps1
# Author      - Jason Gebhart (Updated)
# Script Name - Test-FileServerACLModel.ps1
<#
.SYNOPSIS 
    Tests file server Access Control Lists (ACLs) for compliance and security issues.

.DESCRIPTION
    This script audits file server permissions and Access Control Lists to identify
    potential security risks, compliance violations, and permission inconsistencies.
    It checks for overly permissive access, orphaned accounts, and inheritance issues.

.PARAMETER ComputerName
    Specifies the name of the file server to audit. Default is the local computer.

.PARAMETER SharePaths
    Array of UNC paths or local paths to audit. If not specified, will audit all shares.

.PARAMETER CheckInheritance
    Verify that ACL inheritance is properly configured. Default is true.

.PARAMETER ReportOrphaned
    Include orphaned/unresolved SIDs in the report. Default is true.

.PARAMETER MaxDepth
    Maximum folder depth to scan for permissions. Default is 3 levels.

.EXAMPLE
    .\Test-FileServerACLModel.ps1
    Audits all shares on the local computer.

.EXAMPLE
    .\Test-FileServerACLModel.ps1 -ComputerName "FILESERVER01" -SharePaths @("\\FILESERVER01\Data", "\\FILESERVER01\Home")
    Audits specific shares on a remote file server.

.EXAMPLE
    .\Test-FileServerACLModel.ps1 -CheckInheritance -ReportOrphaned -MaxDepth 2
    Performs comprehensive ACL audit with inheritance and orphaned account checking.
#>

[CmdletBinding()]
param (
    [Parameter(Position=0, Mandatory=$false, ValueFromPipeline = $true)]
    [string]$ComputerName = "$env:COMPUTERNAME",
    
    [Parameter(Mandatory=$false)]
    [string[]]$SharePaths = @(),
    
    [Parameter(Mandatory=$false)]
    [bool]$CheckInheritance = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$ReportOrphaned = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxDepth = 3
)

try {
    Write-Verbose "Starting file server ACL audit for: $ComputerName"
    
    $results = @()
    $errorCount = 0
    $warningCount = 0
    
    # Get shares to audit
    if ($SharePaths.Count -eq 0) {
        Write-Verbose "Getting all SMB shares for audit"
        
        if ($ComputerName -eq $env:COMPUTERNAME) {
            $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.ShareType -eq 'FileSystemDirectory' -and $_.Name -notlike "*$" }
        } else {
            $shares = Get-SmbShare -CimSession $ComputerName -ErrorAction SilentlyContinue | Where-Object { $_.ShareType -eq 'FileSystemDirectory' -and $_.Name -notlike "*$" }
        }
        
        if ($shares) {
            $SharePaths = $shares | ForEach-Object { 
                if ($_.Path) { $_.Path } 
                else { "\\$ComputerName\$($_.Name)" }
            }
        } else {
            Write-Warning "No file shares found to audit"
            $SharePaths = @("C:\")  # Fallback to root if no shares
        }
    }
    
    Write-Verbose "Auditing $($SharePaths.Count) paths"
    
    foreach ($sharePath in $SharePaths) {
        try {
            Write-Verbose "Auditing path: $sharePath"
            
            # Convert UNC paths to local paths for remote execution
            $localPath = $sharePath
            if ($sharePath.StartsWith("\\")) {
                $pathParts = $sharePath.Split('\', [System.StringSplitOptions]::RemoveEmptyEntries)
                if ($pathParts.Length -ge 2) {
                    $localPath = $pathParts[1..($pathParts.Length-1)] -join '\'
                    if (-not $localPath.Contains(':')) {
                        # Assume it's a share name, try to resolve to local path
                        if ($ComputerName -eq $env:COMPUTERNAME) {
                            $share = Get-SmbShare -Name $pathParts[-1] -ErrorAction SilentlyContinue
                            if ($share) { $localPath = $share.Path }
                        }
                    }
                }
            }
            
            # Get ACL information
            $aclData = if ($ComputerName -eq $env:COMPUTERNAME) {
                Get-Acl -Path $localPath -ErrorAction SilentlyContinue
            } else {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    param($path)
                    Get-Acl -Path $path -ErrorAction SilentlyContinue
                } -ArgumentList $localPath -ErrorAction SilentlyContinue
            }
            
            if (-not $aclData) {
                $results += [PSCustomObject]@{
                    Computer = $ComputerName
                    Path = $sharePath
                    IssueType = "AccessDenied"
                    Severity = "Error"
                    Description = "Unable to read ACL - Access denied or path not found"
                    Identity = "N/A"
                    Rights = "N/A"
                    AccessControlType = "N/A"
                    IsInherited = $false
                    InheritanceFlags = "N/A"
                    PropagationFlags = "N/A"
                    Recommendation = "Verify path exists and you have permission to read ACLs"
                }
                $errorCount++
                continue
            }
            
            # Check each access rule
            foreach ($accessRule in $aclData.Access) {
                $issueFound = $false
                $issueType = ""
                $severity = "Info"
                $description = ""
                $recommendation = ""
                
                # Check for orphaned/unresolvable accounts
                if ($ReportOrphaned) {
                    try {
                        $account = $accessRule.IdentityReference
                        if ($account.Value -match "^S-\d-\d+-(\d+-){1,14}\d+$") {
                            $issueFound = $true
                            $issueType = "OrphanedAccount"
                            $severity = "Warning"
                            $description = "Orphaned SID - account may have been deleted"
                            $recommendation = "Remove orphaned SID from ACL"
                            $warningCount++
                        }
                    } catch {
                        # Account resolution failed
                        $issueFound = $true
                        $issueType = "UnresolvableAccount"
                        $severity = "Warning"
                        $description = "Cannot resolve account identity"
                        $recommendation = "Verify account exists and is accessible"
                        $warningCount++
                    }
                }
                
                # Check for overly permissive access
                $highRiskRights = @("FullControl", "Modify", "Write")
                $publicAccounts = @("Everyone", "Authenticated Users", "Domain Users", "Users")
                
                if ($accessRule.AccessControlType -eq "Allow") {
                    $hasHighRisk = $false
                    foreach ($right in $highRiskRights) {
                        if ($accessRule.FileSystemRights -match $right) {
                            $hasHighRisk = $true
                            break
                        }
                    }
                    
                    if ($hasHighRisk) {
                        foreach ($publicAccount in $publicAccounts) {
                            if ($accessRule.IdentityReference.Value -like "*$publicAccount*") {
                                if (-not $issueFound) {
                                    $issueFound = $true
                                    $issueType = "OverlyPermissive"
                                    $severity = "Warning"
                                    $description = "Public group has high-level access rights"
                                    $recommendation = "Review and restrict permissions to specific users/groups"
                                    $warningCount++
                                }
                                break
                            }
                        }
                    }
                }
                
                # Check inheritance issues
                if ($CheckInheritance -and -not $accessRule.IsInherited) {
                    if ($accessRule.InheritanceFlags -eq "None") {
                        if (-not $issueFound) {
                            $issueFound = $true
                            $issueType = "InheritanceIssue"
                            $severity = "Info"
                            $description = "Explicit permission with no inheritance"
                            $recommendation = "Consider using inherited permissions for easier management"
                        }
                    }
                }
                
                # Check for Deny rules (usually indicates problems)
                if ($accessRule.AccessControlType -eq "Deny") {
                    if (-not $issueFound) {
                        $issueFound = $true
                        $issueType = "DenyRule"
                        $severity = "Info"
                        $description = "Explicit Deny rule found"
                        $recommendation = "Review deny rules - they override allow rules"
                    }
                }
                
                # Always report if there's an issue, or if no issues and we want comprehensive output
                if ($issueFound -or $VerbosePreference -eq 'Continue') {
                    if (-not $issueFound) {
                        $issueType = "Normal"
                        $severity = "Info"
                        $description = "Standard file system permission"
                        $recommendation = "No action required"
                    }
                    
                    $results += [PSCustomObject]@{
                        Computer = $ComputerName
                        Path = $sharePath
                        IssueType = $issueType
                        Severity = $severity
                        Description = $description
                        Identity = $accessRule.IdentityReference.Value
                        Rights = $accessRule.FileSystemRights
                        AccessControlType = $accessRule.AccessControlType
                        IsInherited = $accessRule.IsInherited
                        InheritanceFlags = $accessRule.InheritanceFlags
                        PropagationFlags = $accessRule.PropagationFlags
                        Recommendation = $recommendation
                    }
                }
            }
            
        } catch {
            Write-Warning "Error auditing path '$sharePath': $($_.Exception.Message)"
            $results += [PSCustomObject]@{
                Computer = $ComputerName
                Path = $sharePath
                IssueType = "AuditError"
                Severity = "Error"
                Description = "Error during ACL audit: $($_.Exception.Message)"
                Identity = "N/A"
                Rights = "N/A"
                AccessControlType = "N/A"
                IsInherited = $false
                InheritanceFlags = "N/A"
                PropagationFlags = "N/A"
                Recommendation = "Check path accessibility and permissions"
            }
            $errorCount++
        }
    }
    
    # Add summary information
    $summary = [PSCustomObject]@{
        Computer = $ComputerName
        Path = "SUMMARY"
        IssueType = "AuditSummary"
        Severity = if ($errorCount -gt 0) { "Error" } elseif ($warningCount -gt 0) { "Warning" } else { "Info" }
        Description = "ACL Audit completed. Paths audited: $($SharePaths.Count), Errors: $errorCount, Warnings: $warningCount"
        Identity = "System"
        Rights = "N/A"
        AccessControlType = "N/A"
        IsInherited = $false
        InheritanceFlags = "N/A"
        PropagationFlags = "N/A"
        Recommendation = if ($errorCount -gt 0 -or $warningCount -gt 0) { "Review identified issues above" } else { "No issues found" }
    }
    
    # Sort results by severity (errors first, then warnings, then info)
    $sortedResults = @($summary) + ($results | Sort-Object @{
        Expression = {
            switch ($_.Severity) {
                'Error' { 1 }
                'Warning' { 2 }
                'Info' { 3 }
                default { 4 }
            }
        }
    }, Path, Identity)
    
    Write-Verbose "ACL audit completed. Found $($results.Count) ACL entries with $errorCount errors and $warningCount warnings"
    
    return $sortedResults
    
} catch {
    Write-Error "Error during file server ACL audit: $($_.Exception.Message)"
    
    return [PSCustomObject]@{
        Computer = $ComputerName
        Path = "ERROR"
        IssueType = "CriticalError"
        Severity = "Error"
        Description = "Critical error during ACL audit: $($_.Exception.Message)"
        Identity = "System"
        Rights = "N/A"
        AccessControlType = "N/A"
        IsInherited = $false
        InheritanceFlags = "N/A"
        PropagationFlags = "N/A"
        Recommendation = "Check system configuration and retry audit"
    }
}