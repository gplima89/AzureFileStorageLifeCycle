<#
.SYNOPSIS
    Log Analytics Ingestion Module for Azure File Storage Lifecycle Management
    
.DESCRIPTION
    Provides functions for sending file inventory data to Azure Log Analytics
    using the Logs Ingestion API with Data Collection Rules (DCR) and 
    Data Collection Endpoints (DCE) via Managed Identity authentication.
    
.NOTES
    Version: 1.0.0
    Requires: Az.Accounts module for Managed Identity authentication
#>

# Module-level variables for configuration
$script:LogAnalyticsConfig = @{
    DceEndpoint    = ""
    DcrImmutableId = ""
    StreamName     = ""
    TableName      = ""
    BatchSize      = 500
    MaxRetries     = 3
    RetryDelaySeconds = 5
}

function Initialize-LogAnalyticsIngestion {
    <#
    .SYNOPSIS
        Initializes the Log Analytics ingestion configuration
        
    .DESCRIPTION
        Sets up the module with the required DCE endpoint, DCR immutable ID, 
        and stream name for sending data to Log Analytics.
        
    .PARAMETER DceEndpoint
        The Data Collection Endpoint URI (e.g., https://dce-name.region.ingest.monitor.azure.com)
        
    .PARAMETER DcrImmutableId
        The immutable ID of the Data Collection Rule (e.g., dcr-xxxxxxxx...)
        
    .PARAMETER StreamName
        The stream name defined in the DCR (e.g., Custom-TableName_CL)
        
    .PARAMETER TableName
        The target table name in Log Analytics (e.g., StgFileLifeCycle01_CL)
        
    .PARAMETER BatchSize
        Number of records to send per API call (default: 500, max: 1000)
        
    .EXAMPLE
        Initialize-LogAnalyticsIngestion -DceEndpoint "https://dce.region.ingest.monitor.azure.com" `
            -DcrImmutableId "dcr-abc123" -StreamName "Custom-MyTable_CL" -TableName "MyTable_CL"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DceEndpoint,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DcrImmutableId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StreamName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TableName,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1000)]
        [int]$BatchSize = 500
    )
    
    # Remove trailing slash from endpoint if present
    $script:LogAnalyticsConfig.DceEndpoint = $DceEndpoint.TrimEnd('/')
    $script:LogAnalyticsConfig.DcrImmutableId = $DcrImmutableId
    $script:LogAnalyticsConfig.StreamName = $StreamName
    $script:LogAnalyticsConfig.TableName = $TableName
    $script:LogAnalyticsConfig.BatchSize = $BatchSize
    
    Write-Verbose "Log Analytics Ingestion initialized:"
    Write-Verbose "  DCE Endpoint: $($script:LogAnalyticsConfig.DceEndpoint)"
    Write-Verbose "  DCR Immutable ID: $($script:LogAnalyticsConfig.DcrImmutableId)"
    Write-Verbose "  Stream Name: $($script:LogAnalyticsConfig.StreamName)"
    Write-Verbose "  Table Name: $($script:LogAnalyticsConfig.TableName)"
    Write-Verbose "  Batch Size: $($script:LogAnalyticsConfig.BatchSize)"
}

function Get-LogAnalyticsAccessToken {
    <#
    .SYNOPSIS
        Gets an access token for the Logs Ingestion API using Managed Identity
        
    .DESCRIPTION
        Retrieves an OAuth2 access token for the Azure Monitor ingestion scope
        using the Automation Account's system-assigned managed identity.
        
    .OUTPUTS
        Returns the access token string
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    try {
        # Get token for Azure Monitor ingestion scope
        $tokenScope = "https://monitor.azure.com/.default"
        
        # Use Az module to get token via managed identity
        $token = Get-AzAccessToken -ResourceUrl "https://monitor.azure.com" -ErrorAction Stop
        
        if (-not $token -or -not $token.Token) {
            throw "Failed to obtain access token for Azure Monitor"
        }
        
        Write-Verbose "Successfully obtained access token for Azure Monitor"
        return $token.Token
    }
    catch {
        Write-Error "Failed to get access token: $_"
        throw
    }
}

function Send-ToLogAnalytics {
    <#
    .SYNOPSIS
        Sends data to Azure Log Analytics using the Logs Ingestion API
        
    .DESCRIPTION
        Uploads an array of objects to Log Analytics via the configured DCE and DCR.
        Data is sent in batches to respect API limits. Uses Managed Identity for authentication.
        
    .PARAMETER Data
        Array of PSCustomObject entries to send to Log Analytics
        
    .PARAMETER DataType
        Description of the data type being sent (for logging purposes)
        
    .OUTPUTS
        Returns a summary object with upload statistics
        
    .EXAMPLE
        $inventory | Send-ToLogAnalytics -DataType "FileInventory"
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$Data,
        
        [Parameter(Mandatory = $false)]
        [string]$DataType = "Data"
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
            Write-Warning "No data to send to Log Analytics"
            return [PSCustomObject]@{
                Success        = $true
                TotalRecords   = 0
                BatchesSent    = 0
                FailedBatches  = 0
                Duration       = [TimeSpan]::Zero
                Message        = "No data to send"
            }
        }
        
        # Validate configuration
        if (-not $script:LogAnalyticsConfig.DceEndpoint) {
            throw "Log Analytics not initialized. Call Initialize-LogAnalyticsIngestion first."
        }
        
        Write-Verbose "Preparing to send $($allData.Count) $DataType records to Log Analytics"
        
        # Get access token
        $accessToken = Get-LogAnalyticsAccessToken
        
        # Build the ingestion URI
        $uri = "$($script:LogAnalyticsConfig.DceEndpoint)/dataCollectionRules/$($script:LogAnalyticsConfig.DcrImmutableId)/streams/$($script:LogAnalyticsConfig.StreamName)?api-version=2023-01-01"
        
        Write-Verbose "Ingestion URI: $uri"
        
        # Prepare headers
        $headers = @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type"  = "application/json"
        }
        
        # Send data in batches
        $batchSize = $script:LogAnalyticsConfig.BatchSize
        $totalBatches = [Math]::Ceiling($allData.Count / $batchSize)
        $successfulBatches = 0
        $failedBatches = 0
        $totalRecordsSent = 0
        
        for ($i = 0; $i -lt $allData.Count; $i += $batchSize) {
            $batchNumber = [Math]::Floor($i / $batchSize) + 1
            $endIndex = [Math]::Min($i + $batchSize - 1, $allData.Count - 1)
            $batch = $allData[$i..$endIndex]
            
            Write-Verbose "Sending batch $batchNumber of $totalBatches ($($batch.Count) records)"
            
            # Convert to JSON - ensure proper formatting for Log Analytics
            $jsonBody = ConvertTo-LogAnalyticsJson -Data $batch
            
            # Retry logic
            $retryCount = 0
            $success = $false
            
            while (-not $success -and $retryCount -lt $script:LogAnalyticsConfig.MaxRetries) {
                try {
                    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $jsonBody -ErrorAction Stop
                    
                    $success = $true
                    $successfulBatches++
                    $totalRecordsSent += $batch.Count
                    
                    Write-Verbose "Batch $batchNumber sent successfully"
                }
                catch {
                    $retryCount++
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    
                    Write-Warning "Batch $batchNumber failed (attempt $retryCount/$($script:LogAnalyticsConfig.MaxRetries)): Status $statusCode - $($_.Exception.Message)"
                    
                    # Handle specific error codes
                    if ($statusCode -eq 429) {
                        # Rate limited - wait longer
                        $retryAfter = $script:LogAnalyticsConfig.RetryDelaySeconds * $retryCount * 2
                        Write-Warning "Rate limited. Waiting $retryAfter seconds before retry..."
                        Start-Sleep -Seconds $retryAfter
                    }
                    elseif ($statusCode -in @(401, 403)) {
                        # Authentication error - refresh token
                        Write-Warning "Authentication error. Refreshing token..."
                        $accessToken = Get-LogAnalyticsAccessToken
                        $headers["Authorization"] = "Bearer $accessToken"
                        Start-Sleep -Seconds $script:LogAnalyticsConfig.RetryDelaySeconds
                    }
                    elseif ($statusCode -ge 500) {
                        # Server error - retry with backoff
                        Start-Sleep -Seconds ($script:LogAnalyticsConfig.RetryDelaySeconds * $retryCount)
                    }
                    else {
                        # Other errors - log details and break
                        Write-Error "Failed to send batch $batchNumber : $($_.Exception.Message)"
                        break
                    }
                }
            }
            
            if (-not $success) {
                $failedBatches++
                Write-Error "Batch $batchNumber failed after $($script:LogAnalyticsConfig.MaxRetries) retries"
            }
        }
        
        $duration = (Get-Date) - $startTime
        
        $result = [PSCustomObject]@{
            Success        = ($failedBatches -eq 0)
            TotalRecords   = $allData.Count
            RecordsSent    = $totalRecordsSent
            BatchesSent    = $successfulBatches
            TotalBatches   = $totalBatches
            FailedBatches  = $failedBatches
            Duration       = $duration
            DurationSeconds = [math]::Round($duration.TotalSeconds, 2)
            TableName      = $script:LogAnalyticsConfig.TableName
            Message        = if ($failedBatches -eq 0) { 
                "Successfully sent $totalRecordsSent records to $($script:LogAnalyticsConfig.TableName)" 
            } else { 
                "Sent $totalRecordsSent of $($allData.Count) records. $failedBatches batches failed." 
            }
        }
        
        Write-Output "Log Analytics Upload: $($result.Message)"
        return $result
    }
}

function ConvertTo-LogAnalyticsJson {
    <#
    .SYNOPSIS
        Converts PSCustomObject array to JSON format suitable for Log Analytics Ingestion API
        
    .DESCRIPTION
        Ensures proper JSON formatting and adds TimeGenerated field if not present.
        
    .PARAMETER Data
        Array of objects to convert
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Data
    )
    
    $formattedData = foreach ($item in $Data) {
        # Convert to hashtable for manipulation
        $hash = @{}
        
        foreach ($prop in $item.PSObject.Properties) {
            $value = $prop.Value
            
            # Handle DateTime conversion to ISO 8601 format
            if ($value -is [DateTime]) {
                $hash[$prop.Name] = $value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            }
            # Handle null values
            elseif ($null -eq $value) {
                $hash[$prop.Name] = $null
            }
            # Handle boolean values
            elseif ($value -is [bool]) {
                $hash[$prop.Name] = $value
            }
            # Handle numeric values
            elseif ($value -is [int] -or $value -is [long] -or $value -is [double] -or $value -is [decimal]) {
                $hash[$prop.Name] = $value
            }
            # Everything else as string
            else {
                $hash[$prop.Name] = $value.ToString()
            }
        }
        
        # Ensure TimeGenerated exists (required by Log Analytics)
        if (-not $hash.ContainsKey('TimeGenerated')) {
            $hash['TimeGenerated'] = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        }
        
        [PSCustomObject]$hash
    }
    
    return ($formattedData | ConvertTo-Json -Depth 10 -Compress)
}

function Send-FileInventoryToLogAnalytics {
    <#
    .SYNOPSIS
        Sends file inventory data to Azure Log Analytics
        
    .DESCRIPTION
        Convenience function that formats and sends file inventory data 
        to the configured Log Analytics workspace.
        
    .PARAMETER FileInventory
        Collection of file inventory entries from New-FileInventoryEntry
        
    .PARAMETER IncludeExecutionMetadata
        If specified, adds execution metadata to each record
        
    .PARAMETER ExecutionId
        Unique identifier for the execution run
        
    .EXAMPLE
        $inventory | Send-FileInventoryToLogAnalytics -ExecutionId $runId
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$FileInventory,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeExecutionMetadata,
        
        [Parameter(Mandatory = $false)]
        [string]$ExecutionId = [guid]::NewGuid().ToString()
    )
    
    begin {
        $allInventory = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    
    process {
        foreach ($item in $FileInventory) {
            $allInventory.Add($item)
        }
    }
    
    end {
        if ($allInventory.Count -eq 0) {
            Write-Warning "No file inventory data to send"
            return
        }
        
        Write-Output "Preparing $($allInventory.Count) file inventory records for Log Analytics..."
        
        # Add execution metadata if requested
        if ($IncludeExecutionMetadata) {
            $hostName = $env:COMPUTERNAME
            $timestamp = (Get-Date).ToUniversalTime()
            
            foreach ($item in $allInventory) {
                $item | Add-Member -NotePropertyName "ExecutionId" -NotePropertyValue $ExecutionId -Force
                $item | Add-Member -NotePropertyName "ExecutionHost" -NotePropertyValue $hostName -Force
                $item | Add-Member -NotePropertyName "TimeGenerated" -NotePropertyValue $timestamp -Force
            }
        }
        else {
            # At minimum, add TimeGenerated
            $timestamp = (Get-Date).ToUniversalTime()
            foreach ($item in $allInventory) {
                if (-not ($item.PSObject.Properties.Name -contains 'TimeGenerated')) {
                    $item | Add-Member -NotePropertyName "TimeGenerated" -NotePropertyValue $timestamp -Force
                }
            }
        }
        
        # Send to Log Analytics
        $result = $allInventory | Send-ToLogAnalytics -DataType "FileInventory"
        
        return $result
    }
}

function Test-LogAnalyticsConnection {
    <#
    .SYNOPSIS
        Tests the Log Analytics ingestion configuration
        
    .DESCRIPTION
        Sends a test record to validate the DCE, DCR, and authentication are configured correctly.
        
    .EXAMPLE
        Test-LogAnalyticsConnection
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    if (-not $script:LogAnalyticsConfig.DceEndpoint) {
        throw "Log Analytics not initialized. Call Initialize-LogAnalyticsIngestion first."
    }
    
    Write-Output "Testing Log Analytics connection..."
    Write-Output "  DCE Endpoint: $($script:LogAnalyticsConfig.DceEndpoint)"
    Write-Output "  DCR Immutable ID: $($script:LogAnalyticsConfig.DcrImmutableId)"
    Write-Output "  Stream Name: $($script:LogAnalyticsConfig.StreamName)"
    
    # Create a test record
    $testRecord = [PSCustomObject]@{
        TimeGenerated     = (Get-Date).ToUniversalTime()
        StorageAccount    = "TEST_CONNECTION"
        FileShare         = "test"
        Directory         = "/test"
        FilePath          = "/test/connection_test.txt"
        FileName          = "connection_test.txt"
        FileExtension     = ".txt"
        FileCategory      = "Test"
        FileSizeBytes     = 0
        FileSizeKB        = 0
        FileSizeMB        = 0
        FileSizeGB        = 0
        FileSizeTB        = 0
        LastModified      = (Get-Date).ToUniversalTime()
        LastModifiedDate  = (Get-Date).ToString("yyyy-MM-dd")
        Created           = (Get-Date).ToUniversalTime()
        CreatedDate       = (Get-Date).ToString("yyyy-MM-dd")
        AgeInDays         = 0
        AgeBucket         = "0-7 days"
        SizeBucket        = "< 1 KB"
        ContentType       = "text/plain"
        FileHash          = ""
        IsDuplicate       = "No"
        DuplicateCount    = 0
        ScanTimestamp     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        ScanTimestampUTC  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        ExecutionId       = "TEST-" + [guid]::NewGuid().ToString()
        ExecutionHost     = $env:COMPUTERNAME
    }
    
    try {
        $result = @($testRecord) | Send-ToLogAnalytics -DataType "TestConnection"
        
        if ($result.Success) {
            Write-Output "Connection test SUCCESSFUL!"
            Write-Output "  Test record sent to table: $($script:LogAnalyticsConfig.TableName)"
            Write-Output "  Note: It may take a few minutes for the record to appear in Log Analytics"
        }
        else {
            Write-Warning "Connection test FAILED: $($result.Message)"
        }
        
        return $result
    }
    catch {
        Write-Error "Connection test FAILED: $_"
        return [PSCustomObject]@{
            Success = $false
            Message = $_.Exception.Message
        }
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-LogAnalyticsIngestion',
    'Get-LogAnalyticsAccessToken',
    'Send-ToLogAnalytics',
    'ConvertTo-LogAnalyticsJson',
    'Send-FileInventoryToLogAnalytics',
    'Test-LogAnalyticsConnection'
)
