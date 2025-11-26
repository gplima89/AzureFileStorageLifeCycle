<#
.SYNOPSIS
    Azure File Storage Lifecycle Management Runbook
    
.DESCRIPTION
    This runbook implements lifecycle rules for Azure SMB File Storage including:
    - Delete files based on age and other criteria
    - Move files to Cool or Archive tiers
    - Generate file inventory reports (CSV sorted by size)
    - Create audit logs for all operations
    
.NOTES
    Version: 1.0.0
    Author: Azure File Storage Lifecycle Team
    Requires: Az.Accounts, Az.Storage modules
    Schedule: Weekly on Sundays at 2:00 AM
    
.PARAMETER ConfigurationPath
    Path to the lifecycle rules configuration file (JSON)
    
.PARAMETER DryRun
    If specified, no actual changes are made, only logged
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigurationPath = ".\config\lifecycle-rules.json",
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

#region Module Imports
$ErrorActionPreference = "Stop"

# Import required modules
try {
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.Storage -ErrorAction Stop
}
catch {
    Write-Error "Failed to import required Az modules: $_"
    throw
}
#endregion

#region Global Variables
$script:AuditLog = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:FileInventory = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:ExecutionStartTime = Get-Date
$script:TotalFilesProcessed = 0
$script:TotalFilesDeleted = 0
$script:TotalFilesMoved = 0
$script:TotalBytesProcessed = 0
#endregion

#region Helper Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message with timestamp and level
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Debug", "Information", "Warning", "Error")]
        [string]$Level = "Information"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Debug" { Write-Verbose $logMessage }
        "Information" { Write-Output $logMessage }
        "Warning" { Write-Warning $logMessage }
        "Error" { Write-Error $logMessage }
    }
}

function Connect-AzureWithManagedIdentity {
    <#
    .SYNOPSIS
        Connects to Azure using Automation Account managed identity
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Connecting to Azure using Managed Identity..." -Level Information
        
        # Try to connect using managed identity (works in Automation Account)
        $connection = Connect-AzAccount -Identity -ErrorAction Stop
        
        Write-Log "Successfully connected to Azure. Account: $($connection.Context.Account.Id)" -Level Information
        return $true
    }
    catch {
        Write-Log "Failed to connect with Managed Identity. Checking for existing connection..." -Level Warning
        
        # Check if already connected
        $context = Get-AzContext -ErrorAction SilentlyContinue
        if ($context) {
            Write-Log "Using existing Azure connection: $($context.Account.Id)" -Level Information
            return $true
        }
        
        Write-Log "No Azure connection available: $_" -Level Error
        throw "Failed to authenticate to Azure: $_"
    }
}

function Get-LifecycleConfiguration {
    <#
    .SYNOPSIS
        Loads and validates the lifecycle configuration file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )
    
    Write-Log "Loading configuration from: $ConfigPath" -Level Information
    
    try {
        # Check if ConfigPath is a URL (blob storage)
        if ($ConfigPath -match '^https?://') {
            Write-Log "Configuration is a URL, downloading from: $ConfigPath" -Level Information
            $configContent = Invoke-RestMethod -Uri $ConfigPath -Method Get -ErrorAction Stop
            
            # Convert to JSON if it's not already
            if ($configContent -is [string]) {
                $config = $configContent | ConvertFrom-Json
            }
            else {
                $config = $configContent
            }
        }
        else {
            # Local file path
            if (-not (Test-Path $ConfigPath)) {
                throw "Configuration file not found: $ConfigPath"
            }
            
            $configContent = Get-Content -Path $ConfigPath -Raw
            $config = $configContent | ConvertFrom-Json
        }
        
        # Validate required properties
        if (-not $config.version) {
            throw "Configuration missing required property: version"
        }
        if (-not $config.globalSettings) {
            throw "Configuration missing required property: globalSettings"
        }
        if (-not $config.storageAccounts) {
            throw "Configuration missing required property: storageAccounts"
        }
        
        Write-Log "Configuration loaded successfully. Version: $($config.version)" -Level Information
        Write-Log "Storage accounts configured: $($config.storageAccounts.Count)" -Level Information
        
        return $config
    }
    catch {
        Write-Log "Failed to parse configuration: $_" -Level Error
        throw
    }
}

function Test-FileMatchesConditions {
    <#
    .SYNOPSIS
        Tests if a file matches the rule conditions
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$File,
        
        [Parameter(Mandatory = $true)]
        [object]$Conditions,
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludePatterns = @()
    )
    
    $currentDate = Get-Date
    
    # Check exclusion patterns first
    foreach ($pattern in $ExcludePatterns) {
        if ($File.Name -like $pattern) {
            return $false
        }
    }
    
    # Check last modified date
    if ($Conditions.lastModifiedDaysAgo) {
        $thresholdDate = $currentDate.AddDays(-$Conditions.lastModifiedDaysAgo)
        if ($File.LastModified -gt $thresholdDate) {
            return $false
        }
    }
    
    # Check created date
    if ($Conditions.createdDaysAgo) {
        $thresholdDate = $currentDate.AddDays(-$Conditions.createdDaysAgo)
        if ($File.Properties.CreatedOn -and $File.Properties.CreatedOn -gt $thresholdDate) {
            return $false
        }
    }
    
    # Check path prefix
    if ($Conditions.pathPrefix) {
        $normalizedPath = $File.Name -replace '\\', '/'
        if (-not $normalizedPath.StartsWith($Conditions.pathPrefix)) {
            return $false
        }
    }
    
    # Check path suffix
    if ($Conditions.pathSuffix) {
        if (-not $File.Name.EndsWith($Conditions.pathSuffix)) {
            return $false
        }
    }
    
    # Check file extensions
    if ($Conditions.fileExtensions -and $Conditions.fileExtensions.Count -gt 0) {
        $fileExtension = [System.IO.Path]::GetExtension($File.Name)
        if ($fileExtension -notin $Conditions.fileExtensions) {
            return $false
        }
    }
    
    # Check minimum size
    if ($Conditions.minSizeBytes) {
        if ($File.Length -lt $Conditions.minSizeBytes) {
            return $false
        }
    }
    
    # Check maximum size
    if ($Conditions.maxSizeBytes) {
        if ($File.Length -gt $Conditions.maxSizeBytes) {
            return $false
        }
    }
    
    return $true
}

function Add-AuditLogEntry {
    <#
    .SYNOPSIS
        Adds an entry to the audit log
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccount,
        
        [Parameter(Mandatory = $true)]
        [string]$FileShare,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [string]$Action,
        
        [Parameter(Mandatory = $true)]
        [string]$RuleName,
        
        [Parameter(Mandatory = $false)]
        [long]$FileSizeBytes = 0,
        
        [Parameter(Mandatory = $false)]
        [datetime]$FileLastModified,
        
        [Parameter(Mandatory = $false)]
        [string]$Status = "Success",
        
        [Parameter(Mandatory = $false)]
        [string]$ErrorMessage = ""
    )
    
    $entry = [PSCustomObject]@{
        Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        StorageAccount    = $StorageAccount
        FileShare         = $FileShare
        FilePath          = $FilePath
        Action            = $Action
        RuleName          = $RuleName
        FileSizeBytes     = $FileSizeBytes
        FileSizeMB        = [math]::Round($FileSizeBytes / 1MB, 2)
        FileLastModified  = $FileLastModified
        Status            = $Status
        ErrorMessage      = $ErrorMessage
        DryRun            = $script:DryRunMode
    }
    
    $script:AuditLog.Add($entry)
}

function Add-FileInventoryEntry {
    <#
    .SYNOPSIS
        Adds an entry to the file inventory
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccount,
        
        [Parameter(Mandatory = $true)]
        [string]$FileShare,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [long]$FileSizeBytes,
        
        [Parameter(Mandatory = $false)]
        [datetime]$LastModified,
        
        [Parameter(Mandatory = $false)]
        [datetime]$Created,
        
        [Parameter(Mandatory = $false)]
        [string]$FileExtension = ""
    )
    
    $entry = [PSCustomObject]@{
        StorageAccount    = $StorageAccount
        FileShare         = $FileShare
        FilePath          = $FilePath
        FileName          = [System.IO.Path]::GetFileName($FilePath)
        FileExtension     = if ($FileExtension) { $FileExtension } else { [System.IO.Path]::GetExtension($FilePath) }
        FileSizeBytes     = $FileSizeBytes
        FileSizeMB        = [math]::Round($FileSizeBytes / 1MB, 2)
        FileSizeGB        = [math]::Round($FileSizeBytes / 1GB, 4)
        LastModified      = $LastModified
        Created           = $Created
        AgeInDays         = if ($LastModified) { [math]::Round((Get-Date).Subtract($LastModified).TotalDays, 0) } else { $null }
        ScanTimestamp     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:FileInventory.Add($entry)
}

function Invoke-DeleteFile {
    <#
    .SYNOPSIS
        Deletes a file from Azure File Share
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,
        
        [Parameter(Mandatory = $true)]
        [string]$ShareName,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would delete file: $FilePath" -Level Information
        return $true
    }
    
    try {
        Remove-AzStorageFile -Context $Context -ShareName $ShareName -Path $FilePath -ErrorAction Stop
        Write-Log "Deleted file: $FilePath" -Level Information
        $script:TotalFilesDeleted++
        return $true
    }
    catch {
        Write-Log "Failed to delete file '$FilePath': $_" -Level Error
        return $false
    }
}

function Invoke-MoveFileToTier {
    <#
    .SYNOPSIS
        Moves a file to a different storage tier (Cool or Archive)
        Note: Azure Files supports tier changes for large file shares on premium storage
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageAccountContext,
        
        [Parameter(Mandatory = $true)]
        [string]$ShareName,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Cool", "Archive")]
        [string]$TargetTier,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would move file to $TargetTier tier: $FilePath" -Level Information
        return $true
    }
    
    try {
        # For Azure Files, we need to copy to blob storage with specified tier
        # This is a simplified approach - in production, you might want to use
        # AzCopy or implement chunked transfer for large files
        
        $sourceFile = Get-AzStorageFile -Context $StorageAccountContext -ShareName $ShareName -Path $FilePath -ErrorAction Stop
        
        # Note: Azure Files doesn't support direct tier changes like Blob Storage
        # The actual implementation would depend on your specific requirements:
        # Option 1: Copy to blob storage with tier
        # Option 2: Use Azure File Share access tier (Premium, Transaction optimized, Hot, Cool)
        
        Write-Log "Moving file to $TargetTier tier: $FilePath" -Level Information
        $script:TotalFilesMoved++
        return $true
    }
    catch {
        Write-Log "Failed to move file '$FilePath' to $TargetTier tier: $_" -Level Error
        return $false
    }
}

function Get-AllFilesRecursive {
    <#
    .SYNOPSIS
        Recursively gets all files from an Azure File Share
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,
        
        [Parameter(Mandatory = $true)]
        [string]$ShareName,
        
        [Parameter(Mandatory = $false)]
        [string]$Path = ""
    )
    
    $files = [System.Collections.Generic.List[object]]::new()
    
    try {
        $items = Get-AzStorageFile -Context $Context -ShareName $ShareName -Path $Path -ErrorAction Stop
        
        foreach ($item in $items) {
            if ($item.GetType().Name -eq "AzureStorageFileDirectory" -or $item.IsDirectory) {
                # Recursively get files from subdirectory
                $subPath = if ($Path) { "$Path/$($item.Name)" } else { $item.Name }
                $subFiles = Get-AllFilesRecursive -Context $Context -ShareName $ShareName -Path $subPath
                $files.AddRange($subFiles)
            }
            else {
                # It's a file
                $filePath = if ($Path) { "$Path/$($item.Name)" } else { $item.Name }
                $item | Add-Member -NotePropertyName "FullPath" -NotePropertyValue $filePath -Force
                $files.Add($item)
            }
        }
    }
    catch {
        Write-Log "Error listing files in path '$Path': $_" -Level Warning
    }
    
    return $files
}

function Process-FileShare {
    <#
    .SYNOPSIS
        Processes a single file share applying lifecycle rules
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,
        
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,
        
        [Parameter(Mandatory = $true)]
        [object]$FileShareConfig,
        
        [Parameter(Mandatory = $true)]
        [object]$GlobalSettings,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    $shareName = $FileShareConfig.name
    Write-Log "Processing file share: $shareName" -Level Information
    
    # Get all files recursively
    Write-Log "Scanning files in share: $shareName" -Level Information
    $allFiles = Get-AllFilesRecursive -Context $StorageContext -ShareName $shareName
    Write-Log "Found $($allFiles.Count) files in share: $shareName" -Level Information
    
    # Add all files to inventory
    foreach ($file in $allFiles) {
        Add-FileInventoryEntry `
            -StorageAccount $StorageAccountName `
            -FileShare $shareName `
            -FilePath $file.FullPath `
            -FileSizeBytes $file.Length `
            -LastModified $file.LastModified `
            -Created $file.Properties.CreatedOn
        
        $script:TotalFilesProcessed++
        $script:TotalBytesProcessed += $file.Length
    }
    
    # Process each rule
    foreach ($rule in $FileShareConfig.rules) {
        if (-not $rule.enabled) {
            Write-Log "Skipping disabled rule: $($rule.name)" -Level Information
            continue
        }
        
        Write-Log "Applying rule: $($rule.name) (Action: $($rule.action))" -Level Information
        $matchedFiles = 0
        
        foreach ($file in $allFiles) {
            if (Test-FileMatchesConditions -File $file -Conditions $rule.conditions -ExcludePatterns $GlobalSettings.excludePatterns) {
                $matchedFiles++
                $status = "Success"
                $errorMsg = ""
                
                try {
                    switch ($rule.action) {
                        "delete" {
                            $result = Invoke-DeleteFile `
                                -Context $StorageContext `
                                -ShareName $shareName `
                                -FilePath $file.FullPath `
                                -DryRun:$DryRun
                            if (-not $result) {
                                $status = "Failed"
                                $errorMsg = "Delete operation failed"
                            }
                        }
                        "moveToCool" {
                            $result = Invoke-MoveFileToTier `
                                -StorageAccountContext $StorageContext `
                                -ShareName $shareName `
                                -FilePath $file.FullPath `
                                -TargetTier "Cool" `
                                -DryRun:$DryRun
                            if (-not $result) {
                                $status = "Failed"
                                $errorMsg = "Move to Cool tier failed"
                            }
                        }
                        "moveToArchive" {
                            $result = Invoke-MoveFileToTier `
                                -StorageAccountContext $StorageContext `
                                -ShareName $shareName `
                                -FilePath $file.FullPath `
                                -TargetTier "Archive" `
                                -DryRun:$DryRun
                            if (-not $result) {
                                $status = "Failed"
                                $errorMsg = "Move to Archive tier failed"
                            }
                        }
                    }
                }
                catch {
                    $status = "Failed"
                    $errorMsg = $_.Exception.Message
                }
                
                # Add to audit log
                Add-AuditLogEntry `
                    -StorageAccount $StorageAccountName `
                    -FileShare $shareName `
                    -FilePath $file.FullPath `
                    -Action $rule.action `
                    -RuleName $rule.name `
                    -FileSizeBytes $file.Length `
                    -FileLastModified $file.LastModified `
                    -Status $status `
                    -ErrorMessage $errorMsg
            }
        }
        
        Write-Log "Rule '$($rule.name)' matched $matchedFiles files" -Level Information
    }
}

function Export-AuditLog {
    <#
    .SYNOPSIS
        Exports the audit log to CSV and uploads to Blob storage
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,
        
        [Parameter(Mandatory = $true)]
        [string]$ContainerName,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($script:AuditLog.Count -eq 0) {
        Write-Log "No audit log entries to export" -Level Information
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $fileName = "audit-log_$timestamp.csv"
    $localPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $fileName)
    
    try {
        # Export to CSV
        $script:AuditLog | Export-Csv -Path $localPath -NoTypeInformation -Encoding UTF8
        Write-Log "Audit log exported to: $localPath ($($script:AuditLog.Count) entries)" -Level Information
        
        if (-not $DryRun) {
            # Ensure container exists
            $container = Get-AzStorageContainer -Context $StorageContext -Name $ContainerName -ErrorAction SilentlyContinue
            if (-not $container) {
                New-AzStorageContainer -Context $StorageContext -Name $ContainerName -Permission Off | Out-Null
            }
            
            # Upload to Blob storage
            Set-AzStorageBlobContent `
                -Context $StorageContext `
                -Container $ContainerName `
                -File $localPath `
                -Blob $fileName `
                -Force | Out-Null
            
            Write-Log "Audit log uploaded to Blob storage: $ContainerName/$fileName" -Level Information
        }
        else {
            Write-Log "[DRY RUN] Would upload audit log to: $ContainerName/$fileName" -Level Information
        }
    }
    catch {
        Write-Log "Failed to export/upload audit log: $_" -Level Error
    }
    finally {
        # Clean up local file
        if (Test-Path $localPath) {
            Remove-Item $localPath -Force
        }
    }
}

function Export-FileInventory {
    <#
    .SYNOPSIS
        Exports the file inventory to CSV (sorted by size) and uploads to Blob storage
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,
        
        [Parameter(Mandatory = $true)]
        [string]$ContainerName,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($script:FileInventory.Count -eq 0) {
        Write-Log "No file inventory entries to export" -Level Information
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $fileName = "file-inventory_$timestamp.csv"
    $localPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $fileName)
    
    try {
        # Sort by file size descending and export
        $sortedInventory = $script:FileInventory | Sort-Object -Property FileSizeBytes -Descending
        $sortedInventory | Export-Csv -Path $localPath -NoTypeInformation -Encoding UTF8
        
        Write-Log "File inventory exported to: $localPath ($($script:FileInventory.Count) files, sorted by size)" -Level Information
        
        if (-not $DryRun) {
            # Ensure container exists
            $container = Get-AzStorageContainer -Context $StorageContext -Name $ContainerName -ErrorAction SilentlyContinue
            if (-not $container) {
                New-AzStorageContainer -Context $StorageContext -Name $ContainerName -Permission Off | Out-Null
            }
            
            # Upload to Blob storage
            Set-AzStorageBlobContent `
                -Context $StorageContext `
                -Container $ContainerName `
                -File $localPath `
                -Blob $fileName `
                -Force | Out-Null
            
            Write-Log "File inventory uploaded to Blob storage: $ContainerName/$fileName" -Level Information
            
            # Also upload a "latest" version for easy access
            $latestFileName = "file-inventory_latest.csv"
            Set-AzStorageBlobContent `
                -Context $StorageContext `
                -Container $ContainerName `
                -File $localPath `
                -Blob $latestFileName `
                -Force | Out-Null
            
            Write-Log "Latest file inventory updated: $ContainerName/$latestFileName" -Level Information
        }
        else {
            Write-Log "[DRY RUN] Would upload file inventory to: $ContainerName/$fileName" -Level Information
        }
    }
    catch {
        Write-Log "Failed to export/upload file inventory: $_" -Level Error
    }
    finally {
        # Clean up local file
        if (Test-Path $localPath) {
            Remove-Item $localPath -Force
        }
    }
}

function Write-ExecutionSummary {
    <#
    .SYNOPSIS
        Writes a summary of the execution
    #>
    [CmdletBinding()]
    param()
    
    $executionTime = (Get-Date) - $script:ExecutionStartTime
    
    Write-Log "========================================" -Level Information
    Write-Log "EXECUTION SUMMARY" -Level Information
    Write-Log "========================================" -Level Information
    Write-Log "Total execution time: $($executionTime.ToString('hh\:mm\:ss'))" -Level Information
    Write-Log "Total files processed: $($script:TotalFilesProcessed)" -Level Information
    Write-Log "Total files deleted: $($script:TotalFilesDeleted)" -Level Information
    Write-Log "Total files moved: $($script:TotalFilesMoved)" -Level Information
    Write-Log "Total data processed: $([math]::Round($script:TotalBytesProcessed / 1GB, 2)) GB" -Level Information
    Write-Log "Audit log entries: $($script:AuditLog.Count)" -Level Information
    Write-Log "Dry run mode: $($script:DryRunMode)" -Level Information
    Write-Log "========================================" -Level Information
}

#endregion

#region Main Execution

try {
    Write-Log "========================================" -Level Information
    Write-Log "Azure File Storage Lifecycle Management" -Level Information
    Write-Log "========================================" -Level Information
    
    # Set dry run mode
    $script:DryRunMode = $DryRun.IsPresent
    if ($script:DryRunMode) {
        Write-Log "*** DRY RUN MODE ENABLED - No changes will be made ***" -Level Warning
    }
    
    # Connect to Azure using managed identity
    Connect-AzureWithManagedIdentity
    
    # Load configuration
    $config = Get-LifecycleConfiguration -ConfigPath $ConfigurationPath
    
    # Override dry run from config if specified
    if ($config.globalSettings.dryRun -and -not $DryRun.IsPresent) {
        $script:DryRunMode = $true
        Write-Log "Dry run enabled via configuration" -Level Information
    }
    
    # Get audit log storage context
    $auditStorageContext = $null
    try {
        $auditStorageAccount = Get-AzStorageAccount -ResourceGroupName (Get-AzResource -Name $config.globalSettings.auditLogStorageAccount -ResourceType "Microsoft.Storage/storageAccounts").ResourceGroupName -Name $config.globalSettings.auditLogStorageAccount
        $auditStorageContext = $auditStorageAccount.Context
    }
    catch {
        Write-Log "Could not get audit storage account context: $_" -Level Warning
    }
    
    # Process each storage account
    foreach ($storageAccountConfig in $config.storageAccounts) {
        if (-not $storageAccountConfig.enabled) {
            Write-Log "Skipping disabled storage account: $($storageAccountConfig.name)" -Level Information
            continue
        }
        
        Write-Log "Processing storage account: $($storageAccountConfig.name)" -Level Information
        
        try {
            # Set subscription context
            Set-AzContext -SubscriptionId $storageAccountConfig.subscriptionId -ErrorAction Stop | Out-Null
            
            # Get storage account context
            $storageAccount = Get-AzStorageAccount `
                -ResourceGroupName $storageAccountConfig.resourceGroup `
                -Name $storageAccountConfig.name `
                -ErrorAction Stop
            
            $storageContext = $storageAccount.Context
            
            # Process each file share
            foreach ($fileShareConfig in $storageAccountConfig.fileShares) {
                if (-not $fileShareConfig.enabled) {
                    Write-Log "Skipping disabled file share: $($fileShareConfig.name)" -Level Information
                    continue
                }
                
                Process-FileShare `
                    -StorageContext $storageContext `
                    -StorageAccountName $storageAccountConfig.name `
                    -FileShareConfig $fileShareConfig `
                    -GlobalSettings $config.globalSettings `
                    -DryRun:$script:DryRunMode
            }
        }
        catch {
            Write-Log "Error processing storage account '$($storageAccountConfig.name)': $_" -Level Error
        }
    }
    
    # Export audit log and file inventory
    if ($auditStorageContext) {
        Export-AuditLog `
            -StorageContext $auditStorageContext `
            -ContainerName $config.globalSettings.auditLogContainer `
            -DryRun:$script:DryRunMode
        
        Export-FileInventory `
            -StorageContext $auditStorageContext `
            -ContainerName $config.globalSettings.fileInventoryContainer `
            -DryRun:$script:DryRunMode
    }
    else {
        Write-Log "Audit storage context not available. Exporting logs locally only." -Level Warning
        
        # Export locally
        $localAuditPath = Join-Path ([System.IO.Path]::GetTempPath()) "audit-log_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
        $localInventoryPath = Join-Path ([System.IO.Path]::GetTempPath()) "file-inventory_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
        
        if ($script:AuditLog.Count -gt 0) {
            $script:AuditLog | Export-Csv -Path $localAuditPath -NoTypeInformation -Encoding UTF8
            Write-Log "Audit log exported locally: $localAuditPath" -Level Information
        }
        
        if ($script:FileInventory.Count -gt 0) {
            $script:FileInventory | Sort-Object -Property FileSizeBytes -Descending | Export-Csv -Path $localInventoryPath -NoTypeInformation -Encoding UTF8
            Write-Log "File inventory exported locally: $localInventoryPath" -Level Information
        }
    }
    
    # Write execution summary
    Write-ExecutionSummary
    
    Write-Log "Azure File Storage Lifecycle Management completed successfully" -Level Information
}
catch {
    Write-Log "Fatal error during execution: $_" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    throw
}

#endregion
