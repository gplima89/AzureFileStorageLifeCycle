<#
.SYNOPSIS
    Azure File Storage Inventory Scanner Runbook - Optimized for Large Shares
    
.DESCRIPTION
    This runbook scans Azure File Storage accounts and sends inventory data to Log Analytics.
    Optimized for large file shares (2TB+) with streaming, batching, and memory management.
    
    Features:
    - Streams files during traversal (no full in-memory collection)
    - Bounded batching with automatic flush to Log Analytics
    - Pagination support for large directories (5000+ items)
    - Optional MD5 hash computation for duplicate detection
    - Retry logic with exponential backoff for transient errors
    - Memory guards with automatic GC triggers
    - Gzip compression for Log Analytics payloads
    - Progress heartbeat logging
    
.NOTES
    Version: 2.0.0
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
    
.PARAMETER MaxFileSizeForHashMB
    Maximum file size (in MB) for which to calculate hash. Default is 100 MB.
    
.PARAMETER SkipHashComputation
    If true, skips MD5 hash computation entirely. Recommended for large shares.
    
.PARAMETER BatchSize
    Number of records per batch before flushing to Log Analytics. Default is 500.
    
.PARAMETER ThrottleLimit
    Maximum concurrent operations (reserved for future parallel support). Default is 4.
    
.PARAMETER DryRun
    If true, runs in simulation mode (still sends data to Log Analytics for testing)
    
.NOTES
    AUTOMATION VARIABLES (Configure once for all schedules):
    - FileInventory_LogAnalyticsDceEndpoint     : Data Collection Endpoint URI
    - FileInventory_LogAnalyticsDcrImmutableId  : Data Collection Rule immutable ID
    - FileInventory_LogAnalyticsStreamName      : Stream name (e.g., Custom-FileInventory_CL)
    - FileInventory_LogAnalyticsTableName       : Table name (e.g., FileInventory_CL)
    - FileInventory_ExcludePatterns             : Comma-separated patterns to exclude
    
.EXAMPLE
    # Scan with hash computation disabled (recommended for 2TB+ shares)
    Start-AzAutomationRunbook -Name "AzureFileInventoryScanner" -Parameters @{
        StorageAccountName = "mystorageaccount"
        StorageAccountResourceGroup = "my-rg"
        SubscriptionId = "00000000-0000-0000-0000-000000000000"
        SkipHashComputation = $true
    }
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
    [int]$BatchSize = 500,
    
    [Parameter(Mandatory = $false)]
    [int]$ThrottleLimit = 4,
    
    [Parameter(Mandatory = $false)]
    [bool]$DryRun = $false
)

#region Module Imports
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"  # Required for Write-Information to appear in Azure Automation job output

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
    DceEndpoint       = Get-AutomationVariableOrDefault -VariableName "FileInventory_LogAnalyticsDceEndpoint"
    DcrImmutableId    = Get-AutomationVariableOrDefault -VariableName "FileInventory_LogAnalyticsDcrImmutableId"
    StreamName        = Get-AutomationVariableOrDefault -VariableName "FileInventory_LogAnalyticsStreamName"
    TableName         = Get-AutomationVariableOrDefault -VariableName "FileInventory_LogAnalyticsTableName"
    MaxRetries        = 5
    RetryDelaySeconds = 2
    MaxPayloadBytes   = 1048576  # 1MB max payload size
}

# Get exclude patterns from Automation Variable
$excludePatternsStr = Get-AutomationVariableOrDefault -VariableName "FileInventory_ExcludePatterns" -DefaultValue "*.tmp,~`$*,.DS_Store,Thumbs.db"
$script:ExcludePatterns = $excludePatternsStr -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

#endregion

#region Global Variables and Metrics
$script:ExecutionStartTime = Get-Date
$script:ExecutionId = [guid]::NewGuid().ToString()

# Metrics tracking
$script:Metrics = @{
    TotalFilesProcessed   = 0
    TotalBytesProcessed   = [long]0
    TotalFilesSentToLA    = 0
    TotalBatchesSent      = 0
    TotalBatchesFailed    = 0
    TotalDirectories      = 0
    TotalRetries          = 0
    Total404Errors        = 0
    TotalHashesComputed   = 0
    TotalHashesSkipped    = 0
    LastHeartbeat         = Get-Date
    HeartbeatIntervalSec  = 30
}

# Batch collection using List<T> for better performance
$script:CurrentBatch = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:BatchSizeThreshold = $BatchSize
$script:SkipHashing = $SkipHashComputation

# Visited paths for cycle detection (thread-safe if needed later)
$script:VisitedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

#endregion

#region Helper Functions

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Message = "",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Debug", "Information", "Warning", "Error")]
        [string]$Level = "Information"
    )
    
    # Handle empty messages (used for blank lines in output)
    if ([string]::IsNullOrEmpty($Message)) {
        Write-Output " "
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Use Write-Output for Azure Automation compatibility (appears in job output)
    # Write-Information and Write-Host don't reliably appear in Azure Automation job output
    # Note: This function should only be called from void contexts (not inside functions that return values)
    switch ($Level) {
        "Debug" { Write-Verbose $logMessage }
        "Information" { Write-Output $logMessage }
        "Warning" { Write-Warning $logMessage }
        "Error" { Write-Error $logMessage -ErrorAction Continue }
    }
}

function Join-NormalizePath {
    <#
    .SYNOPSIS
        Safely joins path segments, avoiding duplicate segments and double slashes.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BasePath = "",
        
        [Parameter(Mandatory = $true)]
        [string]$ChildPath
    )
    
    # Clean the child path - remove leading/trailing slashes and get just the name
    $cleanChild = $ChildPath.Trim('/').Split('/')[-1]
    
    if ([string]::IsNullOrEmpty($cleanChild)) {
        return $BasePath
    }
    
    if ([string]::IsNullOrEmpty($BasePath)) {
        return $cleanChild
    }
    
    # Clean base path - remove trailing slash
    $cleanBase = $BasePath.TrimEnd('/')
    
    # Check if base already ends with the child (avoid duplication)
    if ($cleanBase.EndsWith("/$cleanChild", [System.StringComparison]::OrdinalIgnoreCase) -or
        $cleanBase.Equals($cleanChild, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $cleanBase
    }
    
    return "$cleanBase/$cleanChild"
}

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Executes a script block with retry logic and exponential backoff.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 2,
        
        [Parameter(Mandatory = $false)]
        [string]$OperationName = "Operation",
        
        [Parameter(Mandatory = $false)]
        [int[]]$RetryableStatusCodes = @(404, 429, 500, 502, 503, 504)
    )
    
    $attempt = 0
    $lastException = $null
    
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            return & $ScriptBlock
        }
        catch {
            $lastException = $_
            $statusCode = if ($_.Exception.Response) { 
                try { $_.Exception.Response.StatusCode.value__ } catch { 0 }
            } else { 0 }
            
            $isRetryable = ($statusCode -in $RetryableStatusCodes) -or 
                           ($_.Exception.Message -match 'timeout|temporarily|transient|retry')
            
            if ($statusCode -eq 404) {
                $script:Metrics.Total404Errors++
            }
            
            if ($isRetryable -and $attempt -lt $MaxRetries) {
                $script:Metrics.TotalRetries++
                $delay = $RetryDelaySeconds * [Math]::Pow(2, $attempt - 1)
                Write-Log "$OperationName failed (attempt $attempt/$MaxRetries), status $statusCode. Retrying in $delay seconds..." -Level Warning
                Start-Sleep -Seconds $delay
            }
            else {
                throw
            }
        }
    }
    
    throw $lastException
}

function Invoke-MemoryGuard {
    <#
    .SYNOPSIS
        Checks memory pressure and triggers garbage collection if needed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$ThresholdMB = 300,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    $currentMemory = [Math]::Round([System.GC]::GetTotalMemory($false) / 1MB, 2)
    
    if ($Force -or $currentMemory -gt $ThresholdMB) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        
        $newMemory = [Math]::Round([System.GC]::GetTotalMemory($true) / 1MB, 2)
        if ($currentMemory -gt $ThresholdMB) {
            Write-Log "Memory guard triggered: ${currentMemory}MB -> ${newMemory}MB" -Level Debug
        }
    }
}

function Write-Heartbeat {
    <#
    .SYNOPSIS
        Writes periodic progress heartbeat logs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    $now = Get-Date
    $elapsed = ($now - $script:Metrics.LastHeartbeat).TotalSeconds
    
    if ($Force -or $elapsed -ge $script:Metrics.HeartbeatIntervalSec) {
        $totalElapsed = ($now - $script:ExecutionStartTime).ToString('hh\:mm\:ss')
        $gbScanned = [Math]::Round($script:Metrics.TotalBytesProcessed / 1GB, 2)
        
        Write-Log "HEARTBEAT | Elapsed: $totalElapsed | Files: $($script:Metrics.TotalFilesProcessed) | Dirs: $($script:Metrics.TotalDirectories) | Sent: $($script:Metrics.TotalFilesSentToLA) | Batches: $($script:Metrics.TotalBatchesSent) | GB: $gbScanned" -Level Information
        
        $script:Metrics.LastHeartbeat = $now
    }
}

function Connect-AzureWithManagedIdentity {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "[AUTH] Attempting to connect to Azure using System-Assigned Managed Identity..." -Level Information
        Write-Log "[AUTH] This runbook requires the Automation Account's Managed Identity to have appropriate RBAC permissions" -Level Information
        $connection = Connect-AzAccount -Identity -ErrorAction Stop
        Write-Log "[AUTH] SUCCESS - Connected to Azure" -Level Information
        Write-Log "[AUTH] Account ID: $($connection.Context.Account.Id)" -Level Information
        Write-Log "[AUTH] Tenant ID: $($connection.Context.Tenant.Id)" -Level Information
        Write-Log "[AUTH] Environment: $($connection.Context.Environment.Name)" -Level Information
        # Don't return anything - this avoids polluting output
    }
    catch {
        Write-Log "[AUTH] Managed Identity connection failed. Checking for existing Azure context..." -Level Warning
        $context = Get-AzContext -ErrorAction SilentlyContinue
        if ($context) {
            Write-Log "[AUTH] Found existing Azure connection - using cached credentials" -Level Information
            Write-Log "[AUTH] Account: $($context.Account.Id)" -Level Information
            # Don't return anything
            return
        }
        Write-Log "[AUTH] FAILED - No Azure connection available" -Level Error
        Write-Log "[AUTH] Error details: $_" -Level Error
        throw "Failed to authenticate to Azure: $_"
    }
}

#endregion

#region Log Analytics Functions

function Get-LogAnalyticsAccessToken {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    $token = Invoke-WithRetry -ScriptBlock {
        Get-AzAccessToken -ResourceUrl "https://monitor.azure.com" -ErrorAction Stop
    } -OperationName "Get-AzAccessToken" -MaxRetries 3
    
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

function ConvertTo-CompressedJson {
    <#
    .SYNOPSIS
        Converts data to JSON and optionally compresses with Gzip.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Data,
        
        [Parameter(Mandatory = $false)]
        [switch]$Compress
    )
    
    # Format data for Log Analytics
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
    
    $json = $formattedData | ConvertTo-Json -Depth 10 -Compress
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    
    if ($Compress -and $jsonBytes.Length -gt 1024) {
        $memoryStream = [System.IO.MemoryStream]::new()
        $gzipStream = [System.IO.Compression.GZipStream]::new($memoryStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $gzipStream.Write($jsonBytes, 0, $jsonBytes.Length)
            $gzipStream.Close()
            return @{
                Bytes = $memoryStream.ToArray()
                IsCompressed = $true
                OriginalSize = $jsonBytes.Length
            }
        }
        finally {
            $gzipStream.Dispose()
            $memoryStream.Dispose()
        }
    }
    
    return @{
        Bytes = $jsonBytes
        IsCompressed = $false
        OriginalSize = $jsonBytes.Length
    }
}

function Send-BatchToLogAnalytics {
    <#
    .SYNOPSIS
        Sends a batch of records to Log Analytics with retry and compression.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[PSCustomObject]]$Batch
    )
    
    if ($Batch.Count -eq 0) {
        return [PSCustomObject]@{ Success = $true; RecordsSent = 0; Message = "Empty batch" }
    }
    
    $batchArray = $Batch.ToArray()
    $payload = ConvertTo-CompressedJson -Data $batchArray -Compress
    
    $uri = "$($script:LogAnalyticsConfig.DceEndpoint)/dataCollectionRules/$($script:LogAnalyticsConfig.DcrImmutableId)/streams/$($script:LogAnalyticsConfig.StreamName)?api-version=2023-01-01"
    
    $accessToken = Get-LogAnalyticsAccessToken
    
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }
    
    if ($payload.IsCompressed) {
        $headers["Content-Encoding"] = "gzip"
    }
    
    $result = Invoke-WithRetry -ScriptBlock {
        Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $payload.Bytes -ErrorAction Stop
        return $true
    } -OperationName "Log Analytics Ingestion" -MaxRetries $script:LogAnalyticsConfig.MaxRetries -RetryDelaySeconds $script:LogAnalyticsConfig.RetryDelaySeconds -RetryableStatusCodes @(429, 500, 502, 503, 504)
    
    return [PSCustomObject]@{
        Success      = $true
        RecordsSent  = $batchArray.Count
        PayloadSize  = $payload.Bytes.Length
        Compressed   = $payload.IsCompressed
        OriginalSize = $payload.OriginalSize
        Message      = "Successfully sent $($batchArray.Count) records"
    }
}

function Invoke-FlushBatchToLogAnalytics {
    <#
    .SYNOPSIS
        Flushes the current batch to Log Analytics and clears it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    if (-not $Force -and $script:CurrentBatch.Count -lt $script:BatchSizeThreshold) {
        return
    }
    
    if ($script:CurrentBatch.Count -eq 0) {
        return
    }
    
    $batchCount = $script:CurrentBatch.Count
    $batchNumber = $script:Metrics.TotalBatchesSent + 1
    
    Write-Log "[BATCH #$batchNumber] Preparing to send $batchCount records to Log Analytics..." -Level Information
    Write-Log "[BATCH #$batchNumber] Cumulative progress: $($script:Metrics.TotalFilesSentToLA) records sent in $($script:Metrics.TotalBatchesSent) batches" -Level Information
    
    try {
        Write-Log "[BATCH #$batchNumber] Converting data to JSON and compressing..." -Level Information
        $result = Send-BatchToLogAnalytics -Batch $script:CurrentBatch
        
        if ($result.Success) {
            $script:Metrics.TotalFilesSentToLA += $result.RecordsSent
            $script:Metrics.TotalBatchesSent++
            $compressionInfo = if ($result.Compressed) { "compressed from $($result.OriginalSize) to $($result.PayloadSize) bytes ($('{0:P0}' -f (1 - $result.PayloadSize/$result.OriginalSize)) reduction)" } else { "$($result.PayloadSize) bytes (uncompressed)" }
            Write-Log "[BATCH #$batchNumber] SUCCESS - Sent $($result.RecordsSent) records, $compressionInfo" -Level Information
        }
    }
    catch {
        $script:Metrics.TotalBatchesFailed++
        Write-Log "[BATCH #$batchNumber] FAILED - Error sending $batchCount records" -Level Warning
        Write-Log "[BATCH #$batchNumber] Error: $_" -Level Warning
    }
    
    # Clear batch and free memory
    Write-Log "[BATCH #$batchNumber] Clearing batch buffer and running memory cleanup..." -Level Debug
    $script:CurrentBatch.Clear()
    Invoke-MemoryGuard -ThresholdMB 250
}

#endregion

#region File Operations Functions

function Get-FileCategory {
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Extension)
    
    $ext = $Extension.ToLower()
    switch -Regex ($ext) {
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
    [OutputType([string])]
    param([int]$AgeInDays)
    
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
    [OutputType([string])]
    param([long]$SizeBytes)
    
    switch ($true) {
        { $SizeBytes -lt 1KB }   { return "< 1 KB" }
        { $SizeBytes -lt 1MB }   { return "1 KB - 1 MB" }
        { $SizeBytes -lt 10MB }  { return "1 MB - 10 MB" }
        { $SizeBytes -lt 100MB } { return "10 MB - 100 MB" }
        { $SizeBytes -lt 500MB } { return "100 MB - 500 MB" }
        { $SizeBytes -lt 1GB }   { return "500 MB - 1 GB" }
        { $SizeBytes -lt 5GB }   { return "1 GB - 5 GB" }
        { $SizeBytes -lt 10GB }  { return "5 GB - 10 GB" }
        default                  { return "10+ GB" }
    }
}

function Test-FileExcluded {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string]$FileName,
        [string[]]$ExcludePatterns
    )
    
    foreach ($pattern in $ExcludePatterns) {
        if ($FileName -like $pattern) { return $true }
    }
    return $false
}

function Get-AzureFileHash {
    <#
    .SYNOPSIS
        Computes MD5 hash for an Azure file, with size limits and error handling.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [object]$Context,
        [string]$ShareName,
        [string]$FilePath,
        [long]$FileSize,
        [long]$MaxSizeForHash
    )
    
    if ($script:SkipHashing) {
        $script:Metrics.TotalHashesSkipped++
        return "SKIPPED"
    }
    
    if ($FileSize -gt $MaxSizeForHash) {
        $script:Metrics.TotalHashesSkipped++
        return "SKIPPED_TOO_LARGE"
    }
    
    try {
        # Try to get hash from file properties first (if blob has Content-MD5)
        $file = Invoke-WithRetry -ScriptBlock {
            Get-AzStorageFile -Context $Context -ShareName $ShareName -Path $FilePath -ErrorAction Stop
        } -OperationName "Get file for hash" -MaxRetries 2
        
        if ($file.FileProperties -and $file.FileProperties.ContentHash -and $file.FileProperties.ContentHash.Length -gt 0) {
            $script:Metrics.TotalHashesComputed++
            return [System.Convert]::ToBase64String($file.FileProperties.ContentHash)
        }
        
        # Download and compute hash for small files only
        if ($FileSize -le 10MB) {
            $tempFile = [System.IO.Path]::GetTempFileName()
            try {
                Get-AzStorageFileContent -Context $Context -ShareName $ShareName -Path $FilePath -Destination $tempFile -Force -ErrorAction Stop | Out-Null
                
                $md5 = [System.Security.Cryptography.MD5]::Create()
                $stream = [System.IO.File]::OpenRead($tempFile)
                try {
                    $hashBytes = $md5.ComputeHash($stream)
                    $script:Metrics.TotalHashesComputed++
                    return [System.BitConverter]::ToString($hashBytes).Replace("-", "")
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
        
        $script:Metrics.TotalHashesSkipped++
        return "SKIPPED_PERFORMANCE"
    }
    catch {
        Write-Log "Hash computation error for '$FilePath': $_" -Level Debug
        return "ERROR"
    }
}

function Add-FileToCurrentBatch {
    <#
    .SYNOPSIS
        Adds a file entry to the current batch and flushes if threshold reached.
    #>
    [CmdletBinding()]
    param(
        [string]$StorageAccount,
        [string]$FileShare,
        [string]$FilePath,
        [long]$FileSizeBytes,
        $LastModified,
        $Created,
        [string]$FileHash
    )
    
    $lastModifiedDT = if ($LastModified -is [DateTimeOffset]) { $LastModified.DateTime } 
                      elseif ($LastModified) { [datetime]$LastModified } 
                      else { $null }
    
    $createdDT = if ($Created -is [DateTimeOffset]) { $Created.DateTime } 
                 elseif ($Created) { [datetime]$Created } 
                 else { $null }
    
    $fileExtension = [System.IO.Path]::GetExtension($FilePath)
    $ageInDays = if ($lastModifiedDT) { [math]::Round((Get-Date).Subtract($lastModifiedDT).TotalDays, 0) } else { 0 }
    
    $entry = [PSCustomObject]@{
        StorageAccount   = $StorageAccount
        FileShare        = $FileShare
        FilePath         = $FilePath
        FileName         = [System.IO.Path]::GetFileName($FilePath)
        FileExtension    = $fileExtension
        FileSizeBytes    = $FileSizeBytes
        FileSizeMB       = [math]::Round($FileSizeBytes / 1MB, 2)
        FileSizeGB       = [math]::Round($FileSizeBytes / 1GB, 4)
        LastModified     = $lastModifiedDT
        Created          = $createdDT
        AgeInDays        = $ageInDays
        FileHash         = $FileHash
        IsDuplicate      = "Unknown"
        DuplicateCount   = 0
        DuplicateGroupId = ""
        FileCategory     = Get-FileCategory -Extension $fileExtension
        AgeBucket        = Get-AgeBucket -AgeInDays $ageInDays
        SizeBucket       = Get-SizeBucket -SizeBytes $FileSizeBytes
        ScanTimestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ExecutionId      = $script:ExecutionId
        TimeGenerated    = (Get-Date).ToUniversalTime()
    }
    
    $script:CurrentBatch.Add($entry)
    $script:Metrics.TotalFilesProcessed++
    $script:Metrics.TotalBytesProcessed += $FileSizeBytes
    
    # Check if we should flush
    if ($script:CurrentBatch.Count -ge $script:BatchSizeThreshold) {
        Invoke-FlushBatchToLogAnalytics
    }
    
    # Periodic heartbeat
    Write-Heartbeat
}

function Invoke-EnumerateDirectoryPaged {
    <#
    .SYNOPSIS
        Enumerates a directory with pagination support for large directories.
        Processes files inline (streaming) to avoid memory accumulation.
    #>
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
        [int]$Depth = 0,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 100
    )
    
    # Depth guard
    if ($Depth -gt $MaxDepth) {
        Write-Log "[DIR] WARNING: Maximum depth ($MaxDepth) reached at '$Path'. Skipping to prevent infinite recursion." -Level Warning
        return
    }
    
    # Cycle detection using normalized path
    $normalizedPath = if ([string]::IsNullOrEmpty($Path)) { "/" } else { "/$Path".ToLower() }
    if (-not $script:VisitedPaths.Add($normalizedPath)) {
        Write-Log "[DIR] WARNING: Cycle detected at '$Path'. This path was already visited. Skipping." -Level Warning
        return
    }
    
    $script:Metrics.TotalDirectories++
    $dirDisplayPath = if ([string]::IsNullOrEmpty($Path)) { "(root)" } else { $Path }
    
    Write-Log "[DIR #$($script:Metrics.TotalDirectories)] Entering: $dirDisplayPath (depth: $Depth)" -Level Information
    
    # Get directory contents with retry
    $items = $null
    try {
        Write-Log "[DIR #$($script:Metrics.TotalDirectories)] Listing contents of '$dirDisplayPath'..." -Level Debug
        $items = Invoke-WithRetry -ScriptBlock {
            if ([string]::IsNullOrEmpty($Path)) {
                Get-AzStorageFile -Context $Context -ShareName $ShareName -ErrorAction Stop
            }
            else {
                $dir = Get-AzStorageFile -Context $Context -ShareName $ShareName -Path $Path -ErrorAction Stop
                if ($null -eq $dir) { return $null }
                $dir | Get-AzStorageFile -ErrorAction Stop
            }
        } -OperationName "List directory '$dirDisplayPath'" -MaxRetries 3 -RetryableStatusCodes @(404, 429, 500, 502, 503, 504)
    }
    catch {
        Write-Log "[DIR #$($script:Metrics.TotalDirectories)] FAILED to enumerate '$dirDisplayPath' after retries" -Level Warning
        Write-Log "[DIR #$($script:Metrics.TotalDirectories)] Error: $_" -Level Warning
        return
    }
    
    if ($null -eq $items) {
        Write-Log "[DIR #$($script:Metrics.TotalDirectories)] Directory '$dirDisplayPath' is empty or inaccessible" -Level Information
        return
    }
    
    # Process items - convert to array to avoid enumeration issues
    $itemArray = @($items)
    $itemCount = $itemArray.Count
    
    # Count files vs directories
    $fileCount = ($itemArray | Where-Object { $_.PSObject.Properties['Length'] -or $_.PSObject.Properties['ContentLength'] }).Count
    $subDirCount = $itemCount - $fileCount
    
    Write-Log "[DIR #$($script:Metrics.TotalDirectories)] Found $itemCount items in '$dirDisplayPath': $fileCount files, $subDirCount subdirectories" -Level Information
    
    if ($itemCount -gt 1000) {
        Write-Log "[DIR #$($script:Metrics.TotalDirectories)] LARGE DIRECTORY DETECTED: $itemCount items. Processing may take a while..." -Level Warning
    }
    
    $processedInDir = 0
    $filesInDir = 0
    $dirsInDir = 0
    foreach ($item in $itemArray) {
        $processedInDir++
        
        # Throttle for very large directories and provide progress updates
        if ($processedInDir % 500 -eq 0) {
            $pctComplete = [math]::Round(($processedInDir / $itemCount) * 100, 1)
            Write-Log "[DIR #$($script:Metrics.TotalDirectories)] Progress in '$dirDisplayPath': $processedInDir/$itemCount items ($pctComplete%)" -Level Information
            Start-Sleep -Milliseconds 50
            Write-Heartbeat
        }
        
        $itemName = $item.Name
        
        # Determine if directory
        $isDirectory = $false
        if ($item.GetType().Name -match 'Directory') { $isDirectory = $true }
        elseif ($item.PSObject.Properties['IsDirectory'] -and $item.IsDirectory) { $isDirectory = $true }
        elseif (-not $item.PSObject.Properties['Length'] -and -not $item.PSObject.Properties['ContentLength']) { $isDirectory = $true }
        elseif ($item.GetType().FullName -like '*CloudFileDirectory*') { $isDirectory = $true }
        
        if ($isDirectory) {
            $dirsInDir++
            # Recurse into subdirectory
            $subPath = Join-NormalizePath -BasePath $Path -ChildPath $itemName
            Write-Log "[DIR #$($script:Metrics.TotalDirectories)] Descending into subdirectory: $itemName" -Level Debug
            Invoke-EnumerateDirectoryPaged `
                -Context $Context `
                -ShareName $ShareName `
                -StorageAccountName $StorageAccountName `
                -Path $subPath `
                -MaxSizeForHash $MaxSizeForHash `
                -Depth ($Depth + 1) `
                -MaxDepth $MaxDepth
        }
        else {
            $filesInDir++
            # Process file
            $cleanName = $itemName.TrimStart('/').Split('/')[-1]
            
            # Check exclusions
            if (Test-FileExcluded -FileName $cleanName -ExcludePatterns $script:ExcludePatterns) {
                continue
            }
            
            $filePath = Join-NormalizePath -BasePath $Path -ChildPath $cleanName
            $fileSize = if ($item.Length) { $item.Length } 
                        elseif ($item.FileProperties.ContentLength) { $item.FileProperties.ContentLength } 
                        else { 0 }
            
            # Compute hash if enabled
            $fileHash = Get-AzureFileHash `
                -Context $Context `
                -ShareName $ShareName `
                -FilePath $filePath `
                -FileSize $fileSize `
                -MaxSizeForHash $MaxSizeForHash
            
            # Add to batch (will auto-flush when threshold reached)
            Add-FileToCurrentBatch `
                -StorageAccount $StorageAccountName `
                -FileShare $ShareName `
                -FilePath $filePath `
                -FileSizeBytes $fileSize `
                -LastModified $item.LastModified `
                -Created $item.FileProperties.SmbProperties.FileCreatedOn `
                -FileHash $fileHash
        }
    }
    
    # Log directory completion
    Write-Log "[DIR #$($script:Metrics.TotalDirectories)] Completed '$dirDisplayPath': processed $filesInDir files, $dirsInDir subdirectories" -Level Information
    
    # Memory guard after processing directory
    if ($itemCount -gt 500) {
        Write-Log "[DIR #$($script:Metrics.TotalDirectories)] Running memory cleanup after large directory..." -Level Debug
        Invoke-MemoryGuard -ThresholdMB 200
    }
}

#endregion

#region Main Execution

try {
    Write-Log "" -Level Information
    Write-Log "################################################################################" -Level Information
    Write-Log "#                                                                              #" -Level Information
    Write-Log "#          AZURE FILE STORAGE INVENTORY SCANNER v2.0                          #" -Level Information
    Write-Log "#                                                                              #" -Level Information
    Write-Log "################################################################################" -Level Information
    Write-Log "" -Level Information
    Write-Log "[CONFIG] Execution Parameters:" -Level Information
    Write-Log "[CONFIG] ----------------------" -Level Information
    Write-Log "[CONFIG] Storage Account:      $StorageAccountName" -Level Information
    Write-Log "[CONFIG] Resource Group:       $StorageAccountResourceGroup" -Level Information
    Write-Log "[CONFIG] Subscription ID:      $SubscriptionId" -Level Information
    Write-Log "[CONFIG] Execution ID:         $script:ExecutionId" -Level Information
    Write-Log "[CONFIG] Start Time:           $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Information
    Write-Log "" -Level Information
    Write-Log "[CONFIG] Processing Settings:" -Level Information
    Write-Log "[CONFIG] ----------------------" -Level Information
    Write-Log "[CONFIG] Batch Size:           $script:BatchSizeThreshold records" -Level Information
    Write-Log "[CONFIG] Hash Computation:     $(if ($script:SkipHashing) { 'DISABLED (faster scan, no duplicate detection)' } else { 'ENABLED (max file size: ' + $MaxFileSizeForHashMB + 'MB)' })" -Level Information
    Write-Log "[CONFIG] Throttle Limit:       $ThrottleLimit (reserved for future parallel support)" -Level Information
    Write-Log "[CONFIG] Exclude Patterns:     $($script:ExcludePatterns -join ', ')" -Level Information
    
    if ($DryRun) {
        Write-Log "" -Level Information
        Write-Log "[CONFIG] *** DRY RUN MODE ENABLED ***" -Level Warning
        Write-Log "[CONFIG] Data will still be sent to Log Analytics for testing purposes" -Level Warning
    }
    
    # Validate Log Analytics configuration
    Write-Log "" -Level Information
    Write-Log "[CONFIG] Log Analytics Configuration:" -Level Information
    Write-Log "[CONFIG] ----------------------" -Level Information
    
    if (-not $script:LogAnalyticsConfig.DceEndpoint -or 
        -not $script:LogAnalyticsConfig.DcrImmutableId -or 
        -not $script:LogAnalyticsConfig.StreamName -or 
        -not $script:LogAnalyticsConfig.TableName) {
        
        Write-Log "[CONFIG] ERROR: Log Analytics configuration is incomplete!" -Level Error
        Write-Log "[CONFIG] Please configure the following Automation Variables:" -Level Error
        Write-Log "[CONFIG]   - FileInventory_LogAnalyticsDceEndpoint     $(if ($script:LogAnalyticsConfig.DceEndpoint) { '[OK]' } else { '[MISSING]' })" -Level Error
        Write-Log "[CONFIG]   - FileInventory_LogAnalyticsDcrImmutableId  $(if ($script:LogAnalyticsConfig.DcrImmutableId) { '[OK]' } else { '[MISSING]' })" -Level Error
        Write-Log "[CONFIG]   - FileInventory_LogAnalyticsStreamName      $(if ($script:LogAnalyticsConfig.StreamName) { '[OK]' } else { '[MISSING]' })" -Level Error
        Write-Log "[CONFIG]   - FileInventory_LogAnalyticsTableName       $(if ($script:LogAnalyticsConfig.TableName) { '[OK]' } else { '[MISSING]' })" -Level Error
        throw "Log Analytics configuration incomplete"
    }
    
    Write-Log "[CONFIG] DCE Endpoint:         $($script:LogAnalyticsConfig.DceEndpoint)" -Level Information
    Write-Log "[CONFIG] DCR Immutable ID:     $($script:LogAnalyticsConfig.DcrImmutableId)" -Level Information
    Write-Log "[CONFIG] Stream Name:          $($script:LogAnalyticsConfig.StreamName)" -Level Information
    Write-Log "[CONFIG] Table Name:           $($script:LogAnalyticsConfig.TableName)" -Level Information
    Write-Log "[CONFIG] Max Retries:          $($script:LogAnalyticsConfig.MaxRetries)" -Level Information
    Write-Log "" -Level Information
    
    # Connect to Azure
    Connect-AzureWithManagedIdentity
    
    # Set subscription context
    Write-Log "[SETUP] Setting Azure subscription context..." -Level Information
    Write-Log "[SETUP] Target Subscription ID: $SubscriptionId" -Level Information
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    Write-Log "[SETUP] Subscription context set successfully" -Level Information
    
    # Get storage account context
    Write-Log "[SETUP] Retrieving storage account access key..." -Level Information
    Write-Log "[SETUP] Storage Account: $StorageAccountName" -Level Information
    Write-Log "[SETUP] Resource Group: $StorageAccountResourceGroup" -Level Information
    $storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $StorageAccountResourceGroup -Name $StorageAccountName -ErrorAction Stop)[0].Value
    Write-Log "[SETUP] Storage account key retrieved successfully" -Level Information
    
    Write-Log "[SETUP] Creating storage context with account key authentication..." -Level Information
    $storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $storageAccountKey -ErrorAction Stop
    Write-Log "[SETUP] Storage context created successfully" -Level Information
    
    # Determine file shares to scan
    Write-Log "[SETUP] Determining file shares to scan..." -Level Information
    $fileSharesToScan = @()
    if ($FileShareNames) {
        $fileSharesToScan = $FileShareNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        Write-Log "[SETUP] User specified $($fileSharesToScan.Count) file share(s) to scan" -Level Information
        foreach ($share in $fileSharesToScan) {
            Write-Log "[SETUP]   - $share" -Level Information
        }
    }
    else {
        Write-Log "[SETUP] No specific shares specified - discovering all file shares in storage account..." -Level Information
        $allShares = Get-AzStorageShare -Context $storageContext -ErrorAction Stop | Where-Object { -not $_.IsSnapshot }
        $fileSharesToScan = $allShares | Select-Object -ExpandProperty Name
        Write-Log "[SETUP] Found $($fileSharesToScan.Count) file share(s) to scan:" -Level Information
        foreach ($share in $fileSharesToScan) {
            $shareInfo = $allShares | Where-Object { $_.Name -eq $share }
            $quotaGB = if ($shareInfo.Quota) { $shareInfo.Quota } else { "N/A" }
            Write-Log "[SETUP]   - $share (Quota: ${quotaGB}GB)" -Level Information
        }
    }
    
    $maxSizeForHash = $MaxFileSizeForHashMB * 1MB
    
    # Process each file share
    $shareIndex = 0
    foreach ($shareName in $fileSharesToScan) {
        $shareIndex++
        Write-Log "" -Level Information
        Write-Log "================================================================================" -Level Information
        Write-Log "[SHARE $shareIndex/$($fileSharesToScan.Count)] STARTING: $shareName" -Level Information
        Write-Log "================================================================================" -Level Information
        
        $shareStartTime = Get-Date
        $filesBeforeShare = $script:Metrics.TotalFilesProcessed
        $bytesBeforeShare = $script:Metrics.TotalBytesProcessed
        
        # Reset visited paths for each share
        Write-Log "[SHARE $shareIndex/$($fileSharesToScan.Count)] Initializing directory tracking for cycle detection..." -Level Information
        $script:VisitedPaths.Clear()
        
        # Enumerate and process files (streaming mode)
        Write-Log "[SHARE $shareIndex/$($fileSharesToScan.Count)] Beginning recursive directory enumeration (streaming mode)..." -Level Information
        Write-Log "[SHARE $shareIndex/$($fileSharesToScan.Count)] Files will be processed and sent to Log Analytics in batches of $($script:BatchSizeThreshold)" -Level Information
        
        Invoke-EnumerateDirectoryPaged `
            -Context $storageContext `
            -ShareName $shareName `
            -StorageAccountName $StorageAccountName `
            -MaxSizeForHash $maxSizeForHash
        
        # Flush remaining batch for this share
        Write-Log "[SHARE $shareIndex/$($fileSharesToScan.Count)] Flushing final batch for this share..." -Level Information
        Invoke-FlushBatchToLogAnalytics -Force
        
        # Share completion summary
        $shareEndTime = Get-Date
        $shareDuration = ($shareEndTime - $shareStartTime).ToString('hh\:mm\:ss')
        $filesInShare = $script:Metrics.TotalFilesProcessed - $filesBeforeShare
        $bytesInShare = $script:Metrics.TotalBytesProcessed - $bytesBeforeShare
        $gbInShare = [math]::Round($bytesInShare / 1GB, 2)
        
        Write-Log "[SHARE $shareIndex/$($fileSharesToScan.Count)] COMPLETED: $shareName" -Level Information
        Write-Log "[SHARE $shareIndex/$($fileSharesToScan.Count)] Duration: $shareDuration | Files: $filesInShare | Size: ${gbInShare}GB" -Level Information
        
        Write-Log "[SHARE $shareIndex/$($fileSharesToScan.Count)] Running post-share memory cleanup..." -Level Information
        Invoke-MemoryGuard -Force
    }
    
    # Final flush
    if ($script:CurrentBatch.Count -gt 0) {
        Write-Log "" -Level Information
        Write-Log "[FINAL] Sending final batch of remaining records..." -Level Information
        Invoke-FlushBatchToLogAnalytics -Force
    }
    
    # Execution summary
    $executionTime = (Get-Date) - $script:ExecutionStartTime
    $avgFilesPerSec = if ($executionTime.TotalSeconds -gt 0) { [math]::Round($script:Metrics.TotalFilesProcessed / $executionTime.TotalSeconds, 1) } else { 0 }
    $avgMBPerSec = if ($executionTime.TotalSeconds -gt 0) { [math]::Round(($script:Metrics.TotalBytesProcessed / 1MB) / $executionTime.TotalSeconds, 2) } else { 0 }
    
    Write-Log "" -Level Information
    Write-Log "################################################################################" -Level Information
    Write-Log "#                           EXECUTION SUMMARY                                  #" -Level Information
    Write-Log "################################################################################" -Level Information
    Write-Log "" -Level Information
    Write-Log "[SUMMARY] Scan Target:" -Level Information
    Write-Log "[SUMMARY] ----------------------" -Level Information
    Write-Log "[SUMMARY] Storage Account:       $StorageAccountName" -Level Information
    Write-Log "[SUMMARY] File Shares Scanned:   $($fileSharesToScan.Count)" -Level Information
    Write-Log "" -Level Information
    Write-Log "[SUMMARY] Performance Metrics:" -Level Information
    Write-Log "[SUMMARY] ----------------------" -Level Information
    Write-Log "[SUMMARY] Total Execution Time:  $($executionTime.ToString('hh\:mm\:ss'))" -Level Information
    Write-Log "[SUMMARY] Total Files Processed: $($script:Metrics.TotalFilesProcessed)" -Level Information
    Write-Log "[SUMMARY] Total Directories:     $($script:Metrics.TotalDirectories)" -Level Information
    Write-Log "[SUMMARY] Total Data Scanned:    $([math]::Round($script:Metrics.TotalBytesProcessed / 1GB, 2)) GB" -Level Information
    Write-Log "[SUMMARY] Avg Throughput:        $avgFilesPerSec files/sec ($avgMBPerSec MB/sec)" -Level Information
    Write-Log "" -Level Information
    Write-Log "[SUMMARY] Log Analytics Ingestion:" -Level Information
    Write-Log "[SUMMARY] ----------------------" -Level Information
    Write-Log "[SUMMARY] Records Sent to LA:    $($script:Metrics.TotalFilesSentToLA)" -Level Information
    Write-Log "[SUMMARY] Batches Sent:          $($script:Metrics.TotalBatchesSent)" -Level Information
    Write-Log "[SUMMARY] Batches Failed:        $($script:Metrics.TotalBatchesFailed)" -Level Information
    Write-Log "[SUMMARY] Success Rate:          $(if ($script:Metrics.TotalBatchesSent -gt 0) { '{0:P1}' -f (($script:Metrics.TotalBatchesSent - $script:Metrics.TotalBatchesFailed) / $script:Metrics.TotalBatchesSent) } else { 'N/A' })" -Level Information
    Write-Log "" -Level Information
    Write-Log "[SUMMARY] Hash Computation:" -Level Information
    Write-Log "[SUMMARY] ----------------------" -Level Information
    Write-Log "[SUMMARY] Hashes Computed:       $($script:Metrics.TotalHashesComputed)" -Level Information
    Write-Log "[SUMMARY] Hashes Skipped:        $($script:Metrics.TotalHashesSkipped)" -Level Information
    Write-Log "" -Level Information
    Write-Log "[SUMMARY] Error Recovery:" -Level Information
    Write-Log "[SUMMARY] ----------------------" -Level Information
    Write-Log "[SUMMARY] Total Retries:         $($script:Metrics.TotalRetries)" -Level Information
    Write-Log "[SUMMARY] Total 404 Errors:      $($script:Metrics.Total404Errors)" -Level Information
    Write-Log "" -Level Information
    Write-Log "################################################################################" -Level Information
    Write-Log "#                         SCAN COMPLETED SUCCESSFULLY                          #" -Level Information
    Write-Log "################################################################################" -Level Information
    
    if (-not $script:SkipHashing) {
        Write-Log "" -Level Information
        Write-Log "[TIP] To find duplicate files, run this query in Log Analytics:" -Level Information
        Write-Log "[TIP] $($script:LogAnalyticsConfig.TableName) | where FileHash !in ('SKIPPED','SKIPPED_TOO_LARGE','ERROR','SKIPPED_PERFORMANCE') | summarize Count=count(), TotalSizeMB=sum(FileSizeMB) by FileHash | where Count > 1 | order by TotalSizeMB desc" -Level Information
    }
}
catch {
    Write-Log "" -Level Error
    Write-Log "################################################################################" -Level Error
    Write-Log "#                              FATAL ERROR                                     #" -Level Error
    Write-Log "################################################################################" -Level Error
    Write-Log "" -Level Error
    Write-Log "[ERROR] The scan failed with an unrecoverable error" -Level Error
    Write-Log "[ERROR] Error Message: $_" -Level Error
    Write-Log "[ERROR] " -Level Error
    Write-Log "[ERROR] Stack Trace:" -Level Error
    Write-Log "[ERROR] $($_.ScriptStackTrace)" -Level Error
    Write-Log "" -Level Error
    Write-Log "[ERROR] Troubleshooting Tips:" -Level Error
    Write-Log "[ERROR] 1. Check that the Managed Identity has 'Storage Account Key Operator' or 'Reader' role on the storage account" -Level Error
    Write-Log "[ERROR] 2. Verify the Automation Variables are correctly configured" -Level Error
    Write-Log "[ERROR] 3. Ensure the DCR has 'Monitoring Metrics Publisher' role assigned to the Managed Identity" -Level Error
    Write-Log "[ERROR] 4. Check if the storage account firewall allows access from Azure services" -Level Error
    Write-Log "" -Level Error
    throw
}

#endregion
