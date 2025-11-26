# Monitoring and Reviewing Audit Logs

This guide covers how to monitor the lifecycle management operations and review audit logs.

## Audit Log Structure

Each lifecycle operation is logged with the following information:

| Field | Description |
|-------|-------------|
| `Timestamp` | When the operation occurred |
| `TimestampUTC` | UTC timestamp |
| `StorageAccount` | Storage account name |
| `FileShare` | File share name |
| `FilePath` | Full path to the file |
| `FileName` | Just the file name |
| `FileExtension` | File extension |
| `Action` | Operation performed (delete, moveToCool, moveToArchive) |
| `RuleName` | Rule that triggered the action |
| `FileSizeBytes` | File size in bytes |
| `FileSizeKB` | File size in KB |
| `FileSizeMB` | File size in MB |
| `FileSizeGB` | File size in GB |
| `FileLastModified` | Last modification date of the file |
| `FileAgeInDays` | Age of the file in days |
| `Status` | Success, Failed, or Skipped |
| `ErrorMessage` | Error details if failed |
| `DryRun` | Whether this was a dry run |
| `ExecutionId` | Unique ID for the execution |
| `HostName` | Host where runbook executed |
| `RunbookName` | Name of the runbook |

## Accessing Audit Logs

### Azure Portal

1. Navigate to your storage account
2. Go to **Containers** → `audit-logs`
3. Download the CSV files

### PowerShell

```powershell
# Download latest audit log
$storageAccount = "yourstorageaccount"
$containerName = "audit-logs"

$ctx = (Get-AzStorageAccount -ResourceGroupName "rg-storage" -Name $storageAccount).Context

# List recent audit logs
$blobs = Get-AzStorageBlob -Container $containerName -Context $ctx | 
    Where-Object { $_.Name -like "audit-log_*.csv" } |
    Sort-Object -Property LastModified -Descending |
    Select-Object -First 5

foreach ($blob in $blobs) {
    Write-Host "$($blob.Name) - $($blob.LastModified)"
}

# Download the latest
$latestBlob = $blobs[0]
Get-AzStorageBlobContent `
    -Container $containerName `
    -Blob $latestBlob.Name `
    -Destination "./audit-logs/" `
    -Context $ctx
```

### Azure Storage Explorer

1. Open Azure Storage Explorer
2. Connect to your storage account
3. Navigate to `audit-logs` container
4. Download and open CSV files

## Analyzing Audit Logs

### PowerShell Analysis

```powershell
# Load audit log
$auditLog = Import-Csv -Path "./audit-log_2024-01-15_02-00-00.csv"

# Summary statistics
Write-Host "Total operations: $($auditLog.Count)"
Write-Host "Successful: $(($auditLog | Where-Object Status -eq 'Success').Count)"
Write-Host "Failed: $(($auditLog | Where-Object Status -eq 'Failed').Count)"

# By action type
$auditLog | Group-Object -Property Action | ForEach-Object {
    Write-Host "$($_.Name): $($_.Count) operations"
}

# By storage account
$auditLog | Group-Object -Property StorageAccount | ForEach-Object {
    $totalSize = ($_.Group | Measure-Object -Property FileSizeMB -Sum).Sum
    Write-Host "$($_.Name): $($_.Count) files, $([math]::Round($totalSize, 2)) MB"
}

# Failed operations
$failures = $auditLog | Where-Object Status -eq 'Failed'
if ($failures) {
    Write-Host "`nFailed Operations:"
    $failures | Format-Table FilePath, Action, ErrorMessage
}

# Top 10 largest deleted files
$auditLog | 
    Where-Object Action -eq 'delete' |
    Sort-Object -Property { [long]$_.FileSizeBytes } -Descending |
    Select-Object -First 10 |
    Format-Table FileName, FileSizeMB, FileLastModified
```

### Excel Analysis

1. Open the CSV file in Excel
2. Enable filters on all columns
3. Create pivot tables for:
   - Operations by Action type
   - Operations by Storage Account
   - Operations by Status
   - Total size processed by rule

## File Inventory Reports

The file inventory CSV provides a complete snapshot of all files:

### Structure

| Field | Description |
|-------|-------------|
| `StorageAccount` | Storage account name |
| `FileShare` | File share name |
| `Directory` | Parent directory |
| `FilePath` | Full file path |
| `FileName` | File name |
| `FileExtension` | Extension |
| `FileCategory` | Category (Documents, Images, etc.) |
| `FileSizeBytes` | Size in bytes |
| `FileSizeKB` | Size in KB |
| `FileSizeMB` | Size in MB |
| `FileSizeGB` | Size in GB |
| `FileSizeTB` | Size in TB |
| `LastModified` | Last modification timestamp |
| `Created` | Creation timestamp |
| `AgeInDays` | Age since last modification |
| `AgeBucket` | Age range category |
| `SizeBucket` | Size range category |
| `ScanTimestamp` | When scan was performed |
| `SizeRank` | Rank by size (1 = largest) |

### Analyzing File Inventory

```powershell
# Load file inventory
$inventory = Import-Csv -Path "./file-inventory_latest.csv"

# Total storage used
$totalGB = ($inventory | Measure-Object -Property FileSizeGB -Sum).Sum
Write-Host "Total storage: $([math]::Round($totalGB, 2)) GB"

# Top 20 largest files
Write-Host "`nTop 20 Largest Files:"
$inventory | 
    Sort-Object -Property { [double]$_.FileSizeGB } -Descending |
    Select-Object -First 20 |
    Format-Table FileName, FileSizeGB, FileCategory, LastModified

# Size by category
Write-Host "`nSize by Category:"
$inventory | Group-Object -Property FileCategory | ForEach-Object {
    $totalSize = ($_.Group | Measure-Object -Property { [double]$_.FileSizeGB } -Sum).Sum
    [PSCustomObject]@{
        Category = $_.Name
        FileCount = $_.Count
        TotalGB = [math]::Round($totalSize, 2)
    }
} | Sort-Object -Property TotalGB -Descending | Format-Table

# Files by age bucket
Write-Host "`nFiles by Age:"
$inventory | Group-Object -Property AgeBucket | ForEach-Object {
    $totalSize = ($_.Group | Measure-Object -Property { [double]$_.FileSizeGB } -Sum).Sum
    [PSCustomObject]@{
        AgeBucket = $_.Name
        FileCount = $_.Count
        TotalGB = [math]::Round($totalSize, 2)
    }
} | Format-Table
```

## Setting Up Alerts

### Azure Monitor Alerts

Create alerts for runbook failures:

```powershell
# Create action group for notifications
$actionGroupName = "ag-lifecycle-alerts"
$resourceGroupName = "rg-file-lifecycle-mgmt"

$emailReceiver = New-AzActionGroupReceiver `
    -Name "AdminEmail" `
    -EmailReceiver `
    -EmailAddress "admin@example.com"

$actionGroup = Set-AzActionGroup `
    -ResourceGroupName $resourceGroupName `
    -Name $actionGroupName `
    -ShortName "lifecycle" `
    -Receiver $emailReceiver

# Create alert rule for failed runbook jobs
$automationAccountId = "/subscriptions/<sub-id>/resourceGroups/$resourceGroupName/providers/Microsoft.Automation/automationAccounts/aa-file-lifecycle"

$condition = New-AzMetricAlertRuleV2Criteria `
    -MetricName "TotalJob" `
    -MetricNamespace "Microsoft.Automation/automationAccounts" `
    -TimeAggregation Total `
    -Operator GreaterThan `
    -Threshold 0 `
    -DimensionSelection @{
        Name = "Status"
        Operator = "Include"
        Values = @("Failed")
    }

Add-AzMetricAlertRuleV2 `
    -Name "RunbookFailureAlert" `
    -ResourceGroupName $resourceGroupName `
    -WindowSize 01:00:00 `
    -Frequency 00:15:00 `
    -TargetResourceId $automationAccountId `
    -Condition $condition `
    -ActionGroupId $actionGroup.Id `
    -Severity 2 `
    -Description "Alert when lifecycle runbook fails"
```

### Custom Alert from Audit Logs

Check for failures after each run:

```powershell
# Script to run after lifecycle job to check for failures
param(
    [string]$StorageAccount,
    [string]$ContainerName = "audit-logs"
)

$ctx = (Get-AzStorageAccount -ResourceGroupName "rg-storage" -Name $StorageAccount).Context

# Get the latest audit log
$latestBlob = Get-AzStorageBlob -Container $ContainerName -Context $ctx |
    Where-Object { $_.Name -like "audit-log_*.csv" } |
    Sort-Object -Property LastModified -Descending |
    Select-Object -First 1

if ($latestBlob) {
    $localPath = [System.IO.Path]::GetTempPath() + $latestBlob.Name
    Get-AzStorageBlobContent -Container $ContainerName -Blob $latestBlob.Name -Destination $localPath -Context $ctx -Force
    
    $auditLog = Import-Csv -Path $localPath
    $failures = $auditLog | Where-Object Status -eq 'Failed'
    
    if ($failures.Count -gt 0) {
        Write-Warning "Found $($failures.Count) failed operations!"
        
        # Send alert (customize based on your notification system)
        $body = "Lifecycle Management Failures:`n`n"
        $failures | ForEach-Object {
            $body += "File: $($_.FilePath)`nAction: $($_.Action)`nError: $($_.ErrorMessage)`n`n"
        }
        
        # Send email, Teams message, etc.
        Write-Host $body
    }
    else {
        Write-Host "All operations completed successfully"
    }
    
    Remove-Item $localPath -Force
}
```

## Dashboard and Reporting

### Weekly Summary Report

Generate a weekly summary:

```powershell
function Get-WeeklySummary {
    param(
        [string]$StorageAccount,
        [string]$AuditContainer = "audit-logs",
        [string]$InventoryContainer = "file-inventory"
    )
    
    $ctx = (Get-AzStorageAccount -ResourceGroupName "rg-storage" -Name $StorageAccount).Context
    
    # Get audit logs from the past week
    $oneWeekAgo = (Get-Date).AddDays(-7)
    $auditBlobs = Get-AzStorageBlob -Container $AuditContainer -Context $ctx |
        Where-Object { $_.LastModified -gt $oneWeekAgo }
    
    $allAuditEntries = @()
    foreach ($blob in $auditBlobs) {
        $localPath = [System.IO.Path]::GetTempPath() + $blob.Name
        Get-AzStorageBlobContent -Container $AuditContainer -Blob $blob.Name -Destination $localPath -Context $ctx -Force | Out-Null
        $allAuditEntries += Import-Csv -Path $localPath
        Remove-Item $localPath -Force
    }
    
    # Generate summary
    $summary = [PSCustomObject]@{
        ReportPeriod = "Last 7 Days"
        TotalOperations = $allAuditEntries.Count
        SuccessfulOperations = ($allAuditEntries | Where-Object Status -eq 'Success').Count
        FailedOperations = ($allAuditEntries | Where-Object Status -eq 'Failed').Count
        FilesDeleted = ($allAuditEntries | Where-Object Action -eq 'delete').Count
        FilesMovedToCool = ($allAuditEntries | Where-Object Action -eq 'moveToCool').Count
        FilesMovedToArchive = ($allAuditEntries | Where-Object Action -eq 'moveToArchive').Count
        TotalSizeProcessedGB = [math]::Round(($allAuditEntries | Measure-Object -Property FileSizeGB -Sum).Sum, 2)
    }
    
    return $summary
}

# Generate report
$summary = Get-WeeklySummary -StorageAccount "yourstorageaccount"
$summary | Format-List
```

### Power BI Dashboard

See the [Power BI Dashboard Guide](../powerbi/README.md) for setting up interactive visualizations.

## Retention and Cleanup

### Automatic Audit Log Cleanup

Add a rule to clean up old audit logs:

```powershell
# Clean up audit logs older than retention period
$retentionDays = 90
$cutoffDate = (Get-Date).AddDays(-$retentionDays)

$ctx = (Get-AzStorageAccount -ResourceGroupName "rg-storage" -Name $storageAccount).Context

$oldBlobs = Get-AzStorageBlob -Container "audit-logs" -Context $ctx |
    Where-Object { $_.LastModified -lt $cutoffDate }

foreach ($blob in $oldBlobs) {
    Remove-AzStorageBlob -Container "audit-logs" -Blob $blob.Name -Context $ctx
    Write-Host "Deleted old audit log: $($blob.Name)"
}
```

### Archive Historical Reports

Move older reports to archive storage for cost savings:

```powershell
# Move audit logs older than 30 days to archive tier
$archiveAfterDays = 30
$cutoffDate = (Get-Date).AddDays(-$archiveAfterDays)

$blobs = Get-AzStorageBlob -Container "audit-logs" -Context $ctx |
    Where-Object { 
        $_.LastModified -lt $cutoffDate -and 
        $_.AccessTier -ne "Archive" 
    }

foreach ($blob in $blobs) {
    $blob.BlobClient.SetAccessTier([Azure.Storage.Blobs.Models.AccessTier]::Archive)
    Write-Host "Archived: $($blob.Name)"
}
```
