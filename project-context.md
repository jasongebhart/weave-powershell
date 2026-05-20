# WeavePowerShell

## Overview
WeavePowerShell is a small collection of standalone Windows Server administration PowerShell scripts, organized by area. It provides focused, reusable tools for file-server ACL and share analysis, server performance statistics, and Windows OS inspection. Each script runs independently — there is no central framework or installer.

## Core Components
- **FileServer/Test-FileServerACLModel.ps1**: Inspects and validates a file server's ACL/permissions model.
- **FileServer/Test-FileServerShareStats.ps1**: Reports statistics for file-server shares.
- **Performance/Get-ServerStats.ps1**: Collects server performance metrics.
- **WinOS/Get-ScheduledTaskModel.ps1**: Enumerates and models Windows scheduled tasks.
- **WinOS/Get-WindowsVersionInfo.ps1**: Reports Windows version and build information.
- **LICENSE**: Repository license.

## Execution Flow
1. Pick the script for the task at hand from the relevant folder (`FileServer/`, `Performance/`, `WinOS/`).
2. Open a PowerShell session on (or with access to) the target Windows server.
3. Run the script directly; it prints or returns its results. Scripts are independent and stateless.

### Execution Example
```
.\WinOS\Get-WindowsVersionInfo.ps1
.\FileServer\Test-FileServerShareStats.ps1
```

## External Dependencies
- **Requirements:** Windows PowerShell / PowerShell 7+, run with sufficient privileges on a Windows server.
- **Inputs:** Target server/share parameters supplied to each script.
- **Outputs:** Console/object output — ACL models, share statistics, performance metrics, scheduled-task and OS version reports.
