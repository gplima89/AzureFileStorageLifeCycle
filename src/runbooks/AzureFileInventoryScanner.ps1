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
    [switch]$DryRun
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
$script:FileInventory = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:ExecutionStartTime = Get-Date
$script:ExecutionId = [guid]::NewGuid().ToString()
$script:TotalFilesProcessed = 0
$script:TotalBytesProcessed = 0
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
        
        [Parameter(Mandatory = $false)]
        [string]$Path = ""
    )
    
    $files = [System.Collections.Generic.List[object]]::new()
    
    try {
        $items = if ([string]::IsNullOrEmpty($Path)) {
            Get-AzStorageFile -Context $Context -ShareName $ShareName -ErrorAction Stop
        } else {
            Get-AzStorageFile -Context $Context -ShareName $ShareName -Path $Path -ErrorAction Stop | 
                Get-AzStorageFile -ErrorAction Stop
        }
        
        foreach ($item in $items) {
            $isDirectory = ($item.GetType().Name -eq "AzureStorageFileDirectory")
            
            if ($isDirectory) {
                $subPath = if ($Path) { "$Path/$($item.Name)" } else { $item.Name }
                $subFiles = Get-AllFilesRecursive -Context $Context -ShareName $ShareName -Path $subPath
                if ($subFiles) {
                    foreach ($subFile in @($subFiles)) {
                        $files.Add($subFile)
                    }
                }
            }
            else {
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
    
    $entry = [PSCustomObject]@{
        StorageAccount    = $StorageAccount
        FileShare         = $FileShare
        FilePath          = $FilePath
        FileName          = [System.IO.Path]::GetFileName($FilePath)
        FileExtension     = if ($FileExtension) { $FileExtension } else { [System.IO.Path]::GetExtension($FilePath) }
        FileSizeBytes     = $FileSizeBytes
        FileSizeMB        = [math]::Round($FileSizeBytes / 1MB, 2)
        FileSizeGB        = [math]::Round($FileSizeBytes / 1GB, 4)
        LastModified      = $lastModifiedDT
        Created           = $createdDT
        AgeInDays         = if ($lastModifiedDT) { [math]::Round((Get-Date).Subtract($lastModifiedDT).TotalDays, 0) } else { $null }
        FileHash          = $FileHash
        IsDuplicate       = "No"
        DuplicateCount    = 0
        DuplicateGroupId  = ""
        ScanTimestamp     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ExecutionId       = $script:ExecutionId
    }
    
    $script:FileInventory.Add($entry)
}

function Find-DuplicateFiles {
    [CmdletBinding()]
    param()
    
    Write-Log "Analyzing files for duplicates..." -Level Information
    $duplicateGroups = @{}
    
    # Group files by size first (quick pre-filter)
    $filesBySize = $script:FileInventory | Group-Object -Property FileSizeBytes | Where-Object { $_.Count -gt 1 }
    
    if ($filesBySize.Count -gt 0) {
        Write-Log "Found $($filesBySize.Count) size groups with potential duplicates" -Level Information
        
        foreach ($sizeGroup in $filesBySize) {
            $filesInGroup = $sizeGroup.Group
            
            # Group by hash within this size group
            $hashGroups = $filesInGroup | 
                Where-Object { $_.FileHash -and $_.FileHash -ne "SKIPPED_TOO_LARGE" -and $_.FileHash -ne "ERROR" -and $_.FileHash -ne "ERROR_NOT_FOUND" } | 
                Group-Object -Property FileHash | 
                Where-Object { $_.Count -gt 1 }
            
            foreach ($hashGroup in $hashGroups) {
                $hash = $hashGroup.Name
                $duplicates = $hashGroup.Group
                
                if ($duplicates.Count -gt 1) {
                    $groupId = [guid]::NewGuid().ToString().Substring(0, 8)
                    $duplicateGroups[$hash] = @{
                        GroupId = $groupId
                        Files = $duplicates
                        Count = $duplicates.Count
                        FileSize = $duplicates[0].FileSizeBytes
                        WastedSpace = $duplicates[0].FileSizeBytes * ($duplicates.Count - 1)
                    }
                    
                    # Update inventory entries
                    foreach ($file in $duplicates) {
                        $file.IsDuplicate = "Yes"
                        $file.DuplicateCount = $duplicates.Count
                        $file.DuplicateGroupId = $groupId
                    }
                }
            }
        }
        
        $totalDuplicateGroups = $duplicateGroups.Count
        $totalDuplicateFiles = ($duplicateGroups.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        $totalWastedSpace = ($duplicateGroups.Values | ForEach-Object { $_.WastedSpace } | Measure-Object -Sum).Sum
        
        Write-Log "Found $totalDuplicateGroups groups of duplicate files" -Level Information
        Write-Log "Total duplicate files: $totalDuplicateFiles (wasting $([math]::Round($totalWastedSpace / 1GB, 2)) GB)" -Level Warning
    }
    else {
        Write-Log "No potential duplicates found (no files with same size)" -Level Information
    }
    
    return $duplicateGroups
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
    
    # Process each file share
    foreach ($shareName in $fileSharestoScan) {
        Write-Log "----------------------------------------" -Level Information
        Write-Log "Processing file share: $shareName" -Level Information
        
        # Get all files recursively
        Write-Log "Scanning files in share: $shareName" -Level Information
        $allFiles = Get-AllFilesRecursive -Context $storageContext -ShareName $shareName
        Write-Log "Found $($allFiles.Count) files in share: $shareName" -Level Information
        
        # Calculate file hashes and add to inventory
        Write-Log "Calculating file hashes and building inventory..." -Level Information
        $processedCount = 0
        $skippedCount = 0
        
        foreach ($file in $allFiles) {
            $processedCount++
            
            # Check exclusion patterns
            if (Test-FileExcluded -FileName $file.Name -ExcludePatterns $script:ExcludePatterns) {
                $skippedCount++
                continue
            }
            
            if ($processedCount % 100 -eq 0) {
                Write-Log "Processed $processedCount of $($allFiles.Count) files..." -Level Information
            }
            
            # Calculate hash for duplicate detection
            $fileHash = Get-AzureFileHash `
                -Context $storageContext `
                -ShareName $shareName `
                -FilePath $file.FullPath `
                -MaxSizeForHash $maxSizeForHash
            
            Add-FileInventoryEntry `
                -StorageAccount $StorageAccountName `
                -FileShare $shareName `
                -FilePath $file.FullPath `
                -FileSizeBytes $file.Length `
                -LastModified $file.LastModified `
                -Created $file.FileProperties.SmbProperties.FileCreatedOn `
                -FileHash $fileHash
            
            $script:TotalFilesProcessed++
            $script:TotalBytesProcessed += $file.Length
        }
        
        Write-Log "File share '$shareName' complete: $processedCount files processed, $skippedCount skipped" -Level Information
    }
    
    # Find duplicate files
    $duplicateGroups = Find-DuplicateFiles
    
    # Enrich inventory with categories and buckets
    Write-Log "Enriching inventory data with categories..." -Level Information
    foreach ($item in $script:FileInventory) {
        $item | Add-Member -NotePropertyName "FileCategory" -NotePropertyValue (Get-FileCategory -Extension $item.FileExtension) -Force
        $item | Add-Member -NotePropertyName "AgeBucket" -NotePropertyValue (Get-AgeBucket -AgeInDays $item.AgeInDays) -Force
        $item | Add-Member -NotePropertyName "SizeBucket" -NotePropertyValue (Get-SizeBucket -SizeBytes $item.FileSizeBytes) -Force
        $item | Add-Member -NotePropertyName "TimeGenerated" -NotePropertyValue (Get-Date).ToUniversalTime() -Force
    }
    
    # Send to Log Analytics
    if ($script:FileInventory.Count -gt 0) {
        Write-Log "Sending $($script:FileInventory.Count) records to Log Analytics..." -Level Information
        
        $laResult = $script:FileInventory | Send-ToLogAnalytics -DataType "FileInventory"
        
        if ($laResult.Success) {
            Write-Log "Successfully sent $($laResult.RecordsSent) records to Log Analytics table '$($laResult.TableName)'" -Level Information
            Write-Log "  Duration: $($laResult.DurationSeconds) seconds, Batches: $($laResult.BatchesSent)/$($laResult.TotalBatches)" -Level Information
        }
        else {
            Write-Log "Failed to send some records to Log Analytics: $($laResult.Message)" -Level Warning
        }
    }
    else {
        Write-Log "No files found to inventory" -Level Warning
    }
    
    # Execution summary
    $executionTime = (Get-Date) - $script:ExecutionStartTime
    
    Write-Log "========================================" -Level Information
    Write-Log "EXECUTION SUMMARY" -Level Information
    Write-Log "========================================" -Level Information
    Write-Log "Storage Account: $StorageAccountName" -Level Information
    Write-Log "File Shares Scanned: $($fileSharestoScan.Count)" -Level Information
    Write-Log "Total execution time: $($executionTime.ToString('hh\:mm\:ss'))" -Level Information
    Write-Log "Total files inventoried: $($script:TotalFilesProcessed)" -Level Information
    Write-Log "Total data scanned: $([math]::Round($script:TotalBytesProcessed / 1GB, 2)) GB" -Level Information
    Write-Log "Duplicate groups found: $($duplicateGroups.Count)" -Level Information
    
    if ($duplicateGroups.Count -gt 0) {
        $totalWasted = ($duplicateGroups.Values | ForEach-Object { $_.WastedSpace } | Measure-Object -Sum).Sum
        Write-Log "Total wasted space (duplicates): $([math]::Round($totalWasted / 1GB, 2)) GB" -Level Warning
    }
    
    Write-Log "========================================" -Level Information
    Write-Log "Azure File Storage Inventory Scanner completed successfully" -Level Information
}
catch {
    Write-Log "Fatal error during execution: $_" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    throw
}

#endregion
