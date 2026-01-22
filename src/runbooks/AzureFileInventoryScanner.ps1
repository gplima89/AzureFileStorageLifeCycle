<#
.SYNOPSIS
    Azure File Storage Inventory Scanner Runbook
    
.DESCRIPTION
    This runbook scans Azure File Storage accounts and sends inventory data to Log Analytics.
    It is designed to be reused across multiple storage accounts by changing parameters per schedule.
    All data from multiple storage accounts is consolidated in a single Log Analytics workspace.
    
    Features:
    - Scans Azure File Shares and collects file metadata
    - Detects duplicate files using MD5 hash comparison
    - Sends inventory data to Log Analytics workspace
    - Uses Managed Identity for authentication (no secrets required)
    - Configurable via parameters (storage account) and Automation Variables (Log Analytics config)
    
.NOTES
    Version: 1.0.0
    Author: Azure File Storage Lifecycle Team
    Requires: Az.Accounts, Az.Storage modules
    
.PARAMETER StorageAccountName
    Name of the Azure Storage Account to scan
    
.PARAMETER StorageAccountResourceGroup
    Resource group containing the storage account
    
.PARAMETER SubscriptionId
    Subscription ID where the storage account is located
    
.PARAMETER FileShareNames
    Comma-separated list of file share names to scan. If empty, scans all file shares.
    Examples: "share1" or "share1,share2,share3"
    
.PARAMETER MaxFileSizeForHashMB
    Maximum file size (in MB) for which to calculate hash. Default is 100 MB.
    Files larger than this will have hash set to "SKIPPED_TOO_LARGE".
    
.PARAMETER DryRun
    If specified, runs in simulation mode (still sends data to Log Analytics)
    
.NOTES
    AUTOMATION VARIABLES (Configure once for all schedules):
    - FileInventory_LogAnalyticsDceEndpoint     : Data Collection Endpoint URI
    - FileInventory_LogAnalyticsDcrImmutableId  : Data Collection Rule immutable ID
    - FileInventory_LogAnalyticsStreamName      : Stream name (e.g., Custom-FileInventory_CL)
    - FileInventory_LogAnalyticsTableName       : Table name (e.g., FileInventory_CL)
    - FileInventory_ExcludePatterns             : Comma-separated patterns to exclude (e.g., "*.tmp,~$*,.DS_Store")
    
.EXAMPLE
    # Example 1: Scan ALL file shares in a storage account
    Start-AzAutomationRunbook -Name "AzureFileInventoryScanner" -Parameters @{
        StorageAccountName = "storageaccounta"
        StorageAccountResourceGroup = "rg-storage-a"
        SubscriptionId = "00000000-0000-0000-0000-000000000000"
    }
    
.EXAMPLE
    # Example 2: Scan a SINGLE specific file share
    Start-AzAutomationRunbook -Name "AzureFileInventoryScanner" -Parameters @{
        StorageAccountName = "storageaccounta"
        StorageAccountResourceGroup = "rg-storage-a"
        SubscriptionId = "00000000-0000-0000-0000-000000000000"
        FileShareNames = "documents"
    }
    
.EXAMPLE
    # Example 3: Scan MULTIPLE specific file shares
    Start-AzAutomationRunbook -Name "AzureFileInventoryScanner" -Parameters @{
        StorageAccountName = "storageaccounta"
        StorageAccountResourceGroup = "rg-storage-a"
        SubscriptionId = "00000000-0000-0000-0000-000000000000"
        FileShareNames = "documents,archives,backups"
    }
    
.EXAMPLE
    # Example 4: Run locally for testing with specific file share
    .\AzureFileInventoryScanner.ps1 `
        -StorageAccountName "mystorageaccount" `
        -StorageAccountResourceGroup "my-rg" `
        -SubscriptionId "00000000-0000-0000-0000-000000000000" `
        -FileShareNames "testshare" `
        -DryRun
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountResourceGroup,
    
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [string]$FileShareNames = "",
    
    [Parameter(Mandatory = $false)]
    [int]$MaxFileSizeForHashMB = 100,
    
    [Parameter(Mandatory = $false)]
    [bool]$SkipHashComputation = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$DryRun = $false
)

#region Module Imports
$ErrorActionPreference = "Stop"

try {
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.Storage -ErrorAction Stop
}
catch {
    Write-Error "Failed to import required Az modules: $_"
    throw
}
#endregion

#region Automation Variable Resolution

function Get-AutomationVariableOrDefault {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$VariableName,
        [string]$DefaultValue = ""
    )
    
    try {
        $value = Get-AutomationVariable -Name $VariableName -ErrorAction SilentlyContinue
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            Write-Verbose "Using Automation Variable: $VariableName"
            return [string]$value
        }
    }
    catch {
        Write-Verbose "Automation Variable '$VariableName' not found or not in Automation Account context"
    }
    
    return [string]$DefaultValue
}

# Resolve Log Analytics configuration from Automation Variables
$script:LogAnalyticsConfig = @{
    DceEndpoint    = Get-AutomationVariableOrDefault -VariableName "FileInventory_LogAnalyticsDceEndpoint"
    DcrImmutableId = Get-AutomationVariableOrDefault -VariableName "FileInventory_LogAnalyticsDcrImmutableId"
    StreamName     = Get-AutomationVariableOrDefault -VariableName "FileInventory_LogAnalyticsStreamName"
    TableName      = Get-AutomationVariableOrDefault -VariableName "FileInventory_LogAnalyticsTableName"
    BatchSize      = 500
    MaxRetries     = 3
    RetryDelaySeconds = 5
}

# Get exclude patterns from Automation Variable
$excludePatternsStr = Get-AutomationVariableOrDefault -VariableName "FileInventory_ExcludePatterns" -DefaultValue "*.tmp,~`$*,.DS_Store,Thumbs.db"
$script:ExcludePatterns = $excludePatternsStr -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

#endregion

#region Global Variables
$script:FileInventoryBatch = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:ExecutionStartTime = Get-Date
$script:ExecutionId = [guid]::NewGuid().ToString()
$script:TotalFilesProcessed = 0
$script:TotalBytesProcessed = 0
$script:TotalFilesSentToLA = 0
$script:BatchesSent = 0

# Batch processing settings - optimized for Azure Automation sandbox (~400MB limit)
$script:BatchSize = 200  # Reduced batch size for memory efficiency
$script:SkipHashing = $false  # Will be set based on parameter

# Note: Hash tracking disabled by default for large shares due to Azure Automation memory limits
# Use SkipHashComputation parameter or run on Hybrid Worker for full duplicate detection
#endregion

#region Helper Functions

function Write-Log {
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
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Connecting to Azure using Managed Identity..." -Level Information
        $connection = Connect-AzAccount -Identity -ErrorAction Stop
        Write-Log "Successfully connected to Azure. Account: $($connection.Context.Account.Id)" -Level Information
        return $true
    }
    catch {
        Write-Log "Failed to connect with Managed Identity. Checking for existing connection..." -Level Warning
        $context = Get-AzContext -ErrorAction SilentlyContinue
        if ($context) {
            Write-Log "Using existing Azure connection: $($context.Account.Id)" -Level Information
            return $true
        }
        Write-Log "No Azure connection available: $_" -Level Error
        throw "Failed to authenticate to Azure: $_"
    }
}

#endregion

#region Log Analytics Functions

function Get-LogAnalyticsAccessToken {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    try {
        $token = Get-AzAccessToken -ResourceUrl "https://monitor.azure.com" -ErrorAction Stop
        
        if (-not $token) {
            throw "Failed to obtain access token for Azure Monitor - token is null"
        }
        
        $tokenValue = $token.Token
        if ($tokenValue -is [System.Security.SecureString]) {
            $tokenValue = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenValue)
            )
        }
        
        if ([string]::IsNullOrEmpty($tokenValue)) {
            throw "Failed to obtain access token for Azure Monitor - token is empty"
        }
        
        return $tokenValue
    }
    catch {
        Write-Error "Failed to get access token: $_"
        throw
    }
}

function ConvertTo-LogAnalyticsJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Data
    )
    
    $formattedData = foreach ($item in $Data) {
        $hash = @{}
        foreach ($prop in $item.PSObject.Properties) {
            $value = $prop.Value
            if ($value -is [DateTime]) {
                $hash[$prop.Name] = $value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            }
            elseif ($null -eq $value) {
                $hash[$prop.Name] = $null
            }
            elseif ($value -is [bool]) {
                $hash[$prop.Name] = $value
            }
            elseif ($value -is [int] -or $value -is [long] -or $value -is [double] -or $value -is [decimal]) {
                $hash[$prop.Name] = $value
            }
            else {
                $hash[$prop.Name] = $value.ToString()
            }
        }
        
        if (-not $hash.ContainsKey('TimeGenerated')) {
            $hash['TimeGenerated'] = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        }
        
        [PSCustomObject]$hash
    }
    return ($formattedData | ConvertTo-Json -Depth 10 -Compress)
}

function Send-ToLogAnalytics {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$Data,
        
        [Parameter(Mandatory = $false)]
        [string]$DataType = "FileInventory"
    )
    
    begin {
        $allData = [System.Collections.Generic.List[PSCustomObject]]::new()
        $startTime = Get-Date
    }
    
    process {
        foreach ($item in $Data) {
            $allData.Add($item)
        }
    }
    
    end {
        if ($allData.Count -eq 0) {
            return [PSCustomObject]@{ Success = $true; TotalRecords = 0; Message = "No data to send" }
        }
        
        if (-not $script:LogAnalyticsConfig.DceEndpoint) {
            throw "Log Analytics DCE Endpoint not configured. Set Automation Variable 'FileInventory_LogAnalyticsDceEndpoint'"
        }
        
        Write-Log "Sending $($allData.Count) $DataType records to Log Analytics..." -Level Information
        
        $accessToken = Get-LogAnalyticsAccessToken
        $uri = "$($script:LogAnalyticsConfig.DceEndpoint)/dataCollectionRules/$($script:LogAnalyticsConfig.DcrImmutableId)/streams/$($script:LogAnalyticsConfig.StreamName)?api-version=2023-01-01"
        
        $headers = @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type"  = "application/json"
        }
        
        $batchSize = $script:LogAnalyticsConfig.BatchSize
        $totalBatches = [Math]::Ceiling($allData.Count / $batchSize)
        $successfulBatches = 0
        $failedBatches = 0
        $totalRecordsSent = 0
        
        for ($i = 0; $i -lt $allData.Count; $i += $batchSize) {
            $batchNumber = [Math]::Floor($i / $batchSize) + 1
            $endIndex = [Math]::Min($i + $batchSize - 1, $allData.Count - 1)
            $batch = $allData[$i..$endIndex]
            
            Write-Log "Sending batch $batchNumber of $totalBatches ($($batch.Count) records)..." -Level Information
            $jsonBody = ConvertTo-LogAnalyticsJson -Data $batch
            
            $retryCount = 0
            $success = $false
            
            while (-not $success -and $retryCount -lt $script:LogAnalyticsConfig.MaxRetries) {
                try {
                    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $jsonBody -ErrorAction Stop
                    $success = $true
                    $successfulBatches++
                    $totalRecordsSent += $batch.Count
                }
                catch {
                    $retryCount++
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    $errorMessage = $_.Exception.Message
                    
                    Write-Warning "Batch $batchNumber failed (attempt $retryCount): Status $statusCode - $errorMessage"
                    
                    if ($statusCode -eq 429) {
                        Start-Sleep -Seconds ($script:LogAnalyticsConfig.RetryDelaySeconds * $retryCount * 2)
                    }
                    elseif ($statusCode -in @(401, 403)) {
                        $accessToken = Get-LogAnalyticsAccessToken
                        $headers["Authorization"] = "Bearer $accessToken"
                        Start-Sleep -Seconds $script:LogAnalyticsConfig.RetryDelaySeconds
                    }
                    elseif ($statusCode -ge 500) {
                        Start-Sleep -Seconds ($script:LogAnalyticsConfig.RetryDelaySeconds * $retryCount)
                    }
                    else {
                        break
                    }
                }
            }
            
            if (-not $success) {
                $failedBatches++
            }
        }
        
        $duration = (Get-Date) - $startTime
        
        return [PSCustomObject]@{
            Success         = ($failedBatches -eq 0)
            TotalRecords    = $allData.Count
            RecordsSent     = $totalRecordsSent
            BatchesSent     = $successfulBatches
            TotalBatches    = $totalBatches
            FailedBatches   = $failedBatches
            DurationSeconds = [math]::Round($duration.TotalSeconds, 2)
            TableName       = $script:LogAnalyticsConfig.TableName
            Message         = if ($failedBatches -eq 0) { "Successfully sent $totalRecordsSent records" } else { "Sent $totalRecordsSent of $($allData.Count) records. $failedBatches batches failed." }
        }
    }
}

#endregion

#region File Operations Functions

function Get-AllFilesRecursive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,
        
        [Parameter(Mandatory = $true)]
        [string]$ShareName,
        
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,
        
        [Parameter(Mandatory = $false)]
        [string]$Path = "",
        
        [Parameter(Mandatory = $false)]
        [long]$MaxSizeForHash = 100MB,
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludePatterns = @(),
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 2,
        
        [Parameter(Mandatory = $false)]
        [int]$Depth = 0
    )
    
    $filesProcessedInDir = 0
    $maxDepth = 50  # Prevent infinite recursion
    
    if ($Depth -gt $maxDepth) {
        Write-Log "Maximum directory depth ($maxDepth) reached at path '$Path'. Skipping." -Level Warning
        return $filesProcessedInDir
    }
    
    # Retry logic for listing directory contents
    $retryCount = 0
    $items = $null
    $success = $false
    
    while (-not $success -and $retryCount -lt $MaxRetries) {
        try {
            $retryCount++
            
            if ([string]::IsNullOrEmpty($Path)) {
                # List root of file share
                $items = Get-AzStorageFile -Context $Context -ShareName $ShareName -ErrorAction Stop
            } 
            else {
                # List contents of a subdirectory - use direct path approach to avoid duplication
                $directory = Get-AzStorageFile -Context $Context -ShareName $ShareName -Path $Path -ErrorAction Stop
                
                if ($null -eq $directory) {
                    Write-Log "Directory not found: '$Path'" -Level Warning
                    return $filesProcessedInDir
                }
                
                # Check if it's actually a directory
                $isDir = $directory.GetType().Name -match 'Directory' -or 
                         ($directory.PSObject.Properties['IsDirectory'] -and $directory.IsDirectory) -or
                         (-not $directory.PSObject.Properties['Length'])
                
                if (-not $isDir) {
                    Write-Log "Path '$Path' is not a directory, skipping" -Level Warning
                    return $filesProcessedInDir
                }
                
                # Get contents of the directory
                $items = $directory | Get-AzStorageFile -ErrorAction Stop
            }
            
            $success = $true
        }
        catch {
            $errorMessage = $_.Exception.Message
            $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "N/A" }
            
            Write-Log "Error listing directory '$Path' (attempt $retryCount/$MaxRetries): $errorMessage" -Level Warning
            
            if ($retryCount -lt $MaxRetries) {
                # Exponential backoff
                $delay = $RetryDelaySeconds * [Math]::Pow(2, $retryCount - 1)
                Write-Log "Retrying in $delay seconds..." -Level Information
                Start-Sleep -Seconds $delay
            }
            else {
                Write-Log "Failed to list directory '$Path' after $MaxRetries attempts. Skipping." -Level Warning
                return $filesProcessedInDir
            }
        }
    }
    
    if ($null -eq $items) {
        return $filesProcessedInDir
    }
    
    # Process items - stream files directly to inventory
    $itemCount = 0
    foreach ($item in $items) {
        $itemCount++
        
        # Throttle for large directories to avoid rate limiting
        if ($itemCount % 1000 -eq 0) {
            Write-Log "Processed $itemCount items in directory '$Path'..." -Level Information
            Start-Sleep -Milliseconds 100  # Small delay to avoid throttling
        }
        
        # Determine if item is a directory using multiple detection methods
        $itemName = $item.Name
        $isDirectory = $false
        
        # Method 1: Check type name
        if ($item.GetType().Name -match 'Directory') {
            $isDirectory = $true
        }
        # Method 2: Check IsDirectory property
        elseif ($item.PSObject.Properties['IsDirectory'] -and $item.IsDirectory) {
            $isDirectory = $true
        }
        # Method 3: Check for absence of Length property (directories don't have size)
        elseif (-not $item.PSObject.Properties['Length'] -and -not $item.PSObject.Properties['ContentLength']) {
            $isDirectory = $true
        }
        # Method 4: Check CloudFile vs CloudFileDirectory
        elseif ($item.GetType().FullName -like '*CloudFileDirectory*') {
            $isDirectory = $true
        }
        
        if ($isDirectory) {
            # Construct subdirectory path - ensure we use only the item name, not any path prefix
            $cleanName = $itemName.TrimStart('/').Split('/')[-1]  # Get just the directory name
            $subPath = if ([string]::IsNullOrEmpty($Path)) { $cleanName } else { "$Path/$cleanName" }
            
            # Prevent path duplication by checking if path already ends with the name
            if ($Path -and $Path.EndsWith("/$cleanName")) {
                Write-Log "Skipping duplicate path: '$subPath' (already processed)" -Level Warning
                continue
            }
            
            # Recursive call with increased depth - files are processed inline
            $subFilesCount = Get-AllFilesRecursive -Context $Context -ShareName $ShareName -StorageAccountName $StorageAccountName -Path $subPath -MaxSizeForHash $MaxSizeForHash -ExcludePatterns $ExcludePatterns -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds -Depth ($Depth + 1)
            $filesProcessedInDir += $subFilesCount
        }
        else {
            # It's a file - process immediately instead of collecting
            $cleanName = $itemName.TrimStart('/').Split('/')[-1]  # Get just the file name
            $filePath = if ([string]::IsNullOrEmpty($Path)) { $cleanName } else { "$Path/$cleanName" }
            
            # Check exclusion patterns
            if (Test-FileExcluded -FileName $cleanName -ExcludePatterns $ExcludePatterns) {
                continue
            }
            
            # Calculate hash for duplicate detection (unless skipped for performance)
            $fileHash = "SKIPPED"
            if (-not $script:SkipHashing) {
                $fileHash = Get-AzureFileHash `
                    -Context $Context `
                    -ShareName $ShareName `
                    -FilePath $filePath `
                    -MaxSizeForHash $MaxSizeForHash
            }
            
            # Add to inventory batch
            Add-FileInventoryEntry `
                -StorageAccount $StorageAccountName `
                -FileShare $ShareName `
                -FilePath $filePath `
                -FileSizeBytes $item.Length `
                -LastModified $item.LastModified `
                -Created $item.FileProperties.SmbProperties.FileCreatedOn `
                -FileHash $fileHash
            
            $filesProcessedInDir++
            
            # Send batch to Log Analytics if threshold reached
            Send-BatchToLogAnalyticsIfNeeded
            
            # Progress logging - every 200 files for smaller batches
            if ($script:TotalFilesProcessed % 200 -eq 0) {
                Write-Log "Progress: $($script:TotalFilesProcessed) files processed, $($script:TotalFilesSentToLA) sent to LA, $([math]::Round($script:TotalBytesProcessed / 1GB, 2)) GB scanned" -Level Information
                
                # Aggressive garbage collection every batch
                [System.GC]::Collect()
            }
        }
    }
    
    # Log progress for directories with many items
    if ($itemCount -gt 100) {
        Write-Log "Completed directory '$Path': $itemCount items, $filesProcessedInDir files processed" -Level Information
    }
    
    return $filesProcessedInDir
}

function Get-AzureFileHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,
        
        [Parameter(Mandatory = $true)]
        [string]$ShareName,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [long]$MaxSizeForHash = 100MB
    )
    
    try {
        $parentPath = [System.IO.Path]::GetDirectoryName($FilePath) -replace '\\', '/'
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        
        $file = $null
        if ([string]::IsNullOrEmpty($parentPath)) {
            $file = Get-AzStorageFile -Context $Context -ShareName $ShareName -ErrorAction Stop | 
                    Where-Object { $_.Name -eq $fileName -and -not $_.IsDirectory } | 
                    Select-Object -First 1
        } else {
            $file = Get-AzStorageFile -Context $Context -ShareName $ShareName -Path $parentPath -ErrorAction Stop | 
                    Get-AzStorageFile -ErrorAction Stop | 
                    Where-Object { $_.Name -eq $fileName -and -not $_.IsDirectory } | 
                    Select-Object -First 1
        }
        
        if (-not $file) {
            return "ERROR_NOT_FOUND"
        }
        
        $fileLength = if ($file.Length) { $file.Length } elseif ($file.FileProperties.ContentLength) { $file.FileProperties.ContentLength } else { 0 }
        if ($fileLength -gt $MaxSizeForHash) {
            return "SKIPPED_TOO_LARGE"
        }
        
        if ($file.FileProperties -and $file.FileProperties.ContentHash -and $file.FileProperties.ContentHash.Length -gt 0) {
            return [System.Convert]::ToBase64String($file.FileProperties.ContentHash)
        }
        
        $tempFile = [System.IO.Path]::GetTempFileName()
        try {
            Get-AzStorageFileContent -Context $Context -ShareName $ShareName -Path $FilePath -Destination $tempFile -Force -ErrorAction Stop | Out-Null
            
            $md5 = [System.Security.Cryptography.MD5]::Create()
            $stream = [System.IO.File]::OpenRead($tempFile)
            try {
                $hashBytes = $md5.ComputeHash($stream)
                $hash = [System.BitConverter]::ToString($hashBytes).Replace("-", "")
                return $hash
            }
            finally {
                $stream.Close()
                $stream.Dispose()
                $md5.Dispose()
            }
        }
        finally {
            if (Test-Path $tempFile) {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-Log "Error calculating hash for '$FilePath': $_" -Level Warning
        return "ERROR"
    }
}

function Test-FileExcluded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludePatterns = @()
    )
    
    foreach ($pattern in $ExcludePatterns) {
        if ($FileName -like $pattern) {
            return $true
        }
    }
    return $false
}

function Add-FileInventoryEntry {
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
        $LastModified,
        
        [Parameter(Mandatory = $false)]
        $Created,
        
        [Parameter(Mandatory = $false)]
        [string]$FileExtension = "",
        
        [Parameter(Mandatory = $false)]
        [string]$FileHash = ""
    )
    
    $lastModifiedDT = if ($LastModified -is [DateTimeOffset]) { $LastModified.DateTime } elseif ($LastModified) { [datetime]$LastModified } else { $null }
    $createdDT = if ($Created -is [DateTimeOffset]) { $Created.DateTime } elseif ($Created) { [datetime]$Created } else { $null }
    
    # Duplicate detection disabled for Azure Automation sandbox memory constraints
    # Duplicates can be detected later via Log Analytics queries on FileHash column
    $isDuplicate = "Unknown"
    $duplicateCount = 0
    
    $fileExtensionValue = if ($FileExtension) { $FileExtension } else { [System.IO.Path]::GetExtension($FilePath) }
    $ageInDays = if ($lastModifiedDT) { [math]::Round((Get-Date).Subtract($lastModifiedDT).TotalDays, 0) } else { $null }
    
    $entry = [PSCustomObject]@{
        StorageAccount    = $StorageAccount
        FileShare         = $FileShare
        FilePath          = $FilePath
        FileName          = [System.IO.Path]::GetFileName($FilePath)
        FileExtension     = $fileExtensionValue
        FileSizeBytes     = $FileSizeBytes
        FileSizeMB        = [math]::Round($FileSizeBytes / 1MB, 2)
        FileSizeGB        = [math]::Round($FileSizeBytes / 1GB, 4)
        LastModified      = $lastModifiedDT
        Created           = $createdDT
        AgeInDays         = $ageInDays
        FileHash          = $FileHash
        IsDuplicate       = $isDuplicate
        DuplicateCount    = $duplicateCount
        DuplicateGroupId  = ""
        FileCategory      = Get-FileCategory -Extension $fileExtensionValue
        AgeBucket         = Get-AgeBucket -AgeInDays $ageInDays
        SizeBucket        = Get-SizeBucket -SizeBytes $FileSizeBytes
        ScanTimestamp     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ExecutionId       = $script:ExecutionId
        TimeGenerated     = (Get-Date).ToUniversalTime()
    }
    
    $script:FileInventoryBatch.Add($entry)
    $script:TotalFilesProcessed++
    $script:TotalBytesProcessed += $FileSizeBytes
}

function Send-BatchToLogAnalyticsIfNeeded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    # Check if we should send batch - use smaller threshold for Azure Automation
    $shouldSend = $Force -or ($script:FileInventoryBatch.Count -ge $script:BatchSize)
    
    if (-not $shouldSend -or $script:FileInventoryBatch.Count -eq 0) {
        return
    }
    
    Write-Log "Sending batch of $($script:FileInventoryBatch.Count) records to Log Analytics (Total sent so far: $script:TotalFilesSentToLA)..." -Level Information
    
    try {
        $laResult = $script:FileInventoryBatch.ToArray() | Send-ToLogAnalytics -DataType "FileInventory"
        
        if ($laResult.Success) {
            $script:TotalFilesSentToLA += $laResult.RecordsSent
            $script:BatchesSent++
            Write-Log "Batch sent successfully. Total records sent: $script:TotalFilesSentToLA" -Level Information
        }
        else {
            Write-Log "Batch send had failures: $($laResult.Message)" -Level Warning
        }
    }
    catch {
        Write-Log "Error sending batch to Log Analytics: $_" -Level Warning
    }
    
    # Clear batch to free memory immediately
    $script:FileInventoryBatch.Clear()
    
    # Force garbage collection to reclaim memory - critical for Azure Automation sandbox
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
}

function Get-FileCategory {
    [CmdletBinding()]
    param(
        [string]$Extension
    )
    
    $extension = $Extension.ToLower()
    switch -Regex ($extension) {
        '\.(doc|docx|pdf|txt|rtf|odt|xls|xlsx|ppt|pptx|csv)$' { return "Documents" }
        '\.(jpg|jpeg|png|gif|bmp|tiff|svg|ico|webp|raw)$' { return "Images" }
        '\.(mp4|avi|mkv|mov|wmv|flv|webm|m4v)$' { return "Videos" }
        '\.(mp3|wav|flac|aac|ogg|wma|m4a)$' { return "Audio" }
        '\.(zip|rar|7z|tar|gz|bz2|xz)$' { return "Archives" }
        '\.(cs|js|ts|py|java|cpp|h|ps1|psm1|sh|json|xml|yaml|yml)$' { return "Code" }
        '\.(exe|dll|msi|bat|cmd|com)$' { return "Executables" }
        '\.(sql|mdf|ldf|bak|db|sqlite)$' { return "Databases" }
        '\.(log|evt|evtx)$' { return "Logs" }
        '\.(tmp|temp|bak|swp|cache)$' { return "Temporary" }
        default { return "Other" }
    }
}

function Get-AgeBucket {
    [CmdletBinding()]
    param(
        [int]$AgeInDays
    )
    
    switch ($AgeInDays) {
        { $_ -le 7 }    { return "0-7 days" }
        { $_ -le 30 }   { return "8-30 days" }
        { $_ -le 90 }   { return "31-90 days" }
        { $_ -le 180 }  { return "91-180 days" }
        { $_ -le 365 }  { return "181-365 days" }
        { $_ -le 730 }  { return "1-2 years" }
        { $_ -le 1825 } { return "2-5 years" }
        default         { return "5+ years" }
    }
}

function Get-SizeBucket {
    [CmdletBinding()]
    param(
        [long]$SizeBytes
    )
    
    switch ($true) {
        { $SizeBytes -lt 1KB }      { return "< 1 KB" }
        { $SizeBytes -lt 1MB }      { return "1 KB - 1 MB" }
        { $SizeBytes -lt 10MB }     { return "1 MB - 10 MB" }
        { $SizeBytes -lt 100MB }    { return "10 MB - 100 MB" }
        { $SizeBytes -lt 500MB }    { return "100 MB - 500 MB" }
        { $SizeBytes -lt 1GB }      { return "500 MB - 1 GB" }
        { $SizeBytes -lt 5GB }      { return "1 GB - 5 GB" }
        { $SizeBytes -lt 10GB }     { return "5 GB - 10 GB" }
        default                     { return "10+ GB" }
    }
}

#endregion

#region Main Execution

try {
    Write-Log "========================================" -Level Information
    Write-Log "Azure File Storage Inventory Scanner" -Level Information
    Write-Log "========================================" -Level Information
    Write-Log "Storage Account: $StorageAccountName" -Level Information
    Write-Log "Resource Group: $StorageAccountResourceGroup" -Level Information
    Write-Log "Subscription: $SubscriptionId" -Level Information
    Write-Log "Execution ID: $script:ExecutionId" -Level Information
    Write-Log "Mode: Streaming (batch size: $script:BatchSize)" -Level Information
    
    # Set hash computation mode
    $script:SkipHashing = $SkipHashComputation
    if ($script:SkipHashing) {
        Write-Log "Hash computation: DISABLED (set SkipHashComputation to `$false to enable)" -Level Warning
    }
    else {
        Write-Log "Hash computation: ENABLED (set SkipHashComputation to `$true to disable for large shares)" -Level Information
    }
    
    if ($DryRun) {
        Write-Log "*** DRY RUN MODE - Data will still be sent to Log Analytics ***" -Level Warning
    }
    
    # Validate Log Analytics configuration
    if (-not $script:LogAnalyticsConfig.DceEndpoint -or 
        -not $script:LogAnalyticsConfig.DcrImmutableId -or 
        -not $script:LogAnalyticsConfig.StreamName -or 
        -not $script:LogAnalyticsConfig.TableName) {
        
        Write-Log "Log Analytics configuration incomplete. Please set the following Automation Variables:" -Level Error
        Write-Log "  - FileInventory_LogAnalyticsDceEndpoint" -Level Error
        Write-Log "  - FileInventory_LogAnalyticsDcrImmutableId" -Level Error
        Write-Log "  - FileInventory_LogAnalyticsStreamName" -Level Error
        Write-Log "  - FileInventory_LogAnalyticsTableName" -Level Error
        throw "Log Analytics configuration incomplete"
    }
    
    Write-Log "Log Analytics Table: $($script:LogAnalyticsConfig.TableName)" -Level Information
    
    # Connect to Azure using managed identity
    Connect-AzureWithManagedIdentity
    
    # Set subscription context
    Write-Log "Setting subscription context..." -Level Information
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    
    # Get storage account context using Storage Account Key
    # Note: OAuth (-UseConnectedAccount) doesn't work reliably with Azure Files
    Write-Log "Getting storage account context..." -Level Information
    $storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $StorageAccountResourceGroup -Name $StorageAccountName -ErrorAction Stop)[0].Value
    $storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $storageAccountKey -ErrorAction Stop
    
    # Determine which file shares to scan
    $fileSharestoScan = @()
    if ($FileShareNames) {
        $fileSharestoScan = $FileShareNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        Write-Log "Scanning specified file shares: $($fileSharestoScan -join ', ')" -Level Information
    }
    else {
        # Get all file shares
        $allShares = Get-AzStorageShare -Context $storageContext -ErrorAction Stop | Where-Object { -not $_.IsSnapshot }
        $fileSharestoScan = $allShares | Select-Object -ExpandProperty Name
        Write-Log "Scanning all file shares: $($fileSharestoScan -join ', ')" -Level Information
    }
    
    $maxSizeForHash = $MaxFileSizeForHashMB * 1MB
    
    # Process each file share using streaming approach
    foreach ($shareName in $fileSharestoScan) {
        Write-Log "----------------------------------------" -Level Information
        Write-Log "Processing file share: $shareName" -Level Information
        Write-Log "Scanning and processing files (streaming mode)..." -Level Information
        
        # Get all files recursively - this now processes files inline and sends batches to LA
        $filesInShare = Get-AllFilesRecursive `
            -Context $storageContext `
            -ShareName $shareName `
            -StorageAccountName $StorageAccountName `
            -MaxSizeForHash $maxSizeForHash `
            -ExcludePatterns $script:ExcludePatterns
        
        Write-Log "File share '$shareName' complete: $filesInShare files processed" -Level Information
        
        # Force GC after each file share
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
    
    # Send any remaining records in the batch
    if ($script:FileInventoryBatch.Count -gt 0) {
        Write-Log "Sending final batch of $($script:FileInventoryBatch.Count) records..." -Level Information
        Send-BatchToLogAnalyticsIfNeeded -Force
    }
    
    # Execution summary
    $executionTime = (Get-Date) - $script:ExecutionStartTime
    
    Write-Log "========================================" -Level Information
    Write-Log "EXECUTION SUMMARY" -Level Information
    Write-Log "========================================" -Level Information
    Write-Log "Storage Account: $StorageAccountName" -Level Information
    Write-Log "File Shares Scanned: $($fileSharestoScan.Count)" -Level Information
    Write-Log "Total execution time: $($executionTime.ToString('hh\:mm\:ss'))" -Level Information
    Write-Log "Total files processed: $($script:TotalFilesProcessed)" -Level Information
    Write-Log "Total files sent to Log Analytics: $($script:TotalFilesSentToLA)" -Level Information
    Write-Log "Total batches sent: $($script:BatchesSent)" -Level Information
    Write-Log "Total data scanned: $([math]::Round($script:TotalBytesProcessed / 1GB, 2)) GB" -Level Information
    Write-Log "Hash computation: $(if ($script:SkipHashing) { 'Skipped' } else { 'Enabled' })" -Level Information
    
    Write-Log "========================================" -Level Information
    Write-Log "Azure File Storage Inventory Scanner completed successfully" -Level Information
    Write-Log "NOTE: To find duplicates, query Log Analytics: StgFileLifeCycle01_CL | where FileHash != 'SKIPPED' | summarize count() by FileHash | where count_ > 1" -Level Information
}
catch {
    Write-Log "Fatal error during execution: $_" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    throw
}

#endregion
