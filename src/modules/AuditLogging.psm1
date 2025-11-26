<#
.SYNOPSIS
    Audit Logging Module for Azure File Storage Lifecycle Management
    
.DESCRIPTION
    Provides functions for creating and managing audit logs for file operations
    
.NOTES
    Version: 1.0.0
#>

function New-AuditLogEntry {
    <#
    .SYNOPSIS
        Creates a new audit log entry object
        
    .PARAMETER StorageAccount
        Name of the storage account
        
    .PARAMETER FileShare
        Name of the file share
        
    .PARAMETER FilePath
        Full path to the file
        
    .PARAMETER Action
        Action performed (delete, moveToCool, moveToArchive)
        
    .PARAMETER RuleName
        Name of the rule that triggered the action
        
    .PARAMETER FileSizeBytes
        Size of the file in bytes
        
    .PARAMETER FileLastModified
        Last modified timestamp of the file
        
    .PARAMETER Status
        Status of the operation (Success, Failed, Skipped)
        
    .PARAMETER ErrorMessage
        Error message if operation failed
        
    .PARAMETER DryRun
        Whether this was a dry run
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccount,
        
        [Parameter(Mandatory = $true)]
        [string]$FileShare,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("delete", "moveToCool", "moveToArchive", "scan")]
        [string]$Action,
        
        [Parameter(Mandatory = $false)]
        [string]$RuleName = "",
        
        [Parameter(Mandatory = $false)]
        [long]$FileSizeBytes = 0,
        
        [Parameter(Mandatory = $false)]
        [datetime]$FileLastModified,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Success", "Failed", "Skipped")]
        [string]$Status = "Success",
        
        [Parameter(Mandatory = $false)]
        [string]$ErrorMessage = "",
        
        [Parameter(Mandatory = $false)]
        [bool]$DryRun = $false
    )
    
    return [PSCustomObject]@{
        Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TimestampUTC      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        StorageAccount    = $StorageAccount
        FileShare         = $FileShare
        FilePath          = $FilePath
        FileName          = [System.IO.Path]::GetFileName($FilePath)
        FileExtension     = [System.IO.Path]::GetExtension($FilePath)
        Action            = $Action
        RuleName          = $RuleName
        FileSizeBytes     = $FileSizeBytes
        FileSizeKB        = [math]::Round($FileSizeBytes / 1KB, 2)
        FileSizeMB        = [math]::Round($FileSizeBytes / 1MB, 2)
        FileSizeGB        = [math]::Round($FileSizeBytes / 1GB, 4)
        FileLastModified  = $FileLastModified
        FileAgeInDays     = if ($FileLastModified) { [math]::Round((Get-Date).Subtract($FileLastModified).TotalDays, 0) } else { $null }
        Status            = $Status
        ErrorMessage      = $ErrorMessage
        DryRun            = $DryRun
        ExecutionId       = $script:ExecutionId
        HostName          = $env:COMPUTERNAME
        RunbookName       = "AzureFileStorageLifecycle"
    }
}

function Export-AuditLogToCsv {
    <#
    .SYNOPSIS
        Exports audit log entries to a CSV file
        
    .PARAMETER AuditLogEntries
        Collection of audit log entries
        
    .PARAMETER OutputPath
        Path to save the CSV file
        
    .PARAMETER Append
        Whether to append to existing file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$AuditLogEntries,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Append
    )
    
    begin {
        $allEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    
    process {
        foreach ($entry in $AuditLogEntries) {
            $allEntries.Add($entry)
        }
    }
    
    end {
        if ($allEntries.Count -eq 0) {
            Write-Verbose "No audit log entries to export"
            return
        }
        
        $exportParams = @{
            Path              = $OutputPath
            NoTypeInformation = $true
            Encoding          = "UTF8"
        }
        
        if ($Append -and (Test-Path $OutputPath)) {
            $exportParams['Append'] = $true
        }
        
        $allEntries | Export-Csv @exportParams
        Write-Verbose "Exported $($allEntries.Count) audit log entries to: $OutputPath"
    }
}

function Get-AuditLogSummary {
    <#
    .SYNOPSIS
        Generates a summary of audit log entries
        
    .PARAMETER AuditLogEntries
        Collection of audit log entries
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$AuditLogEntries
    )
    
    $summary = [PSCustomObject]@{
        TotalEntries       = $AuditLogEntries.Count
        SuccessfulActions  = ($AuditLogEntries | Where-Object { $_.Status -eq "Success" }).Count
        FailedActions      = ($AuditLogEntries | Where-Object { $_.Status -eq "Failed" }).Count
        SkippedActions     = ($AuditLogEntries | Where-Object { $_.Status -eq "Skipped" }).Count
        DeleteActions      = ($AuditLogEntries | Where-Object { $_.Action -eq "delete" }).Count
        MoveToCoolActions  = ($AuditLogEntries | Where-Object { $_.Action -eq "moveToCool" }).Count
        MoveToArchiveActions = ($AuditLogEntries | Where-Object { $_.Action -eq "moveToArchive" }).Count
        TotalBytesProcessed = ($AuditLogEntries | Measure-Object -Property FileSizeBytes -Sum).Sum
        UniqueStorageAccounts = ($AuditLogEntries | Select-Object -ExpandProperty StorageAccount -Unique).Count
        UniqueFileShares   = ($AuditLogEntries | Select-Object -ExpandProperty FileShare -Unique).Count
        GeneratedAt        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    return $summary
}

# Initialize execution ID for tracking
$script:ExecutionId = [guid]::NewGuid().ToString()

# Export functions
Export-ModuleMember -Function @(
    'New-AuditLogEntry',
    'Export-AuditLogToCsv',
    'Get-AuditLogSummary'
)
