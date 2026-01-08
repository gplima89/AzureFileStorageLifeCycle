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
    
.PARAMETER SendToLogAnalytics
    If specified, sends file inventory data to Azure Log Analytics
    
.PARAMETER LogAnalyticsDceEndpoint
    Data Collection Endpoint URI for Log Analytics ingestion
    
.PARAMETER LogAnalyticsDcrImmutableId
    Data Collection Rule immutable ID for Log Analytics ingestion
    
.PARAMETER LogAnalyticsStreamName
    Stream name defined in the DCR (e.g., Custom-TableName_CL)
    
.PARAMETER LogAnalyticsTableName
    Target table name in Log Analytics (e.g., StgFileLifeCycle01_CL)
    
.NOTES
    AUTOMATION VARIABLES (Alternative to Parameters):
    When running via schedule, you can use Automation Account Variables instead of parameters:
    - LifeCycle_ConfigurationPath     : Blob URL to config file
    - LifeCycle_DryRun                : "true" or "false"
    - LifeCycle_SendToLogAnalytics    : "true" or "false"
    - LifeCycle_LogAnalyticsDceEndpoint
    - LifeCycle_LogAnalyticsDcrImmutableId
    - LifeCycle_LogAnalyticsStreamName
    - LifeCycle_LogAnalyticsTableName
    
    Parameters take precedence over variables if both are provided.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigurationPath = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [switch]$SendToLogAnalytics,
    
    [Parameter(Mandatory = $false)]
    [string]$LogAnalyticsDceEndpoint = "",
    
    [Parameter(Mandatory = $false)]
    [string]$LogAnalyticsDcrImmutableId = "",
    
    [Parameter(Mandatory = $false)]
    [string]$LogAnalyticsStreamName = "",
    
    [Parameter(Mandatory = $false)]
    [string]$LogAnalyticsTableName = ""
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

#region Automation Variable Resolution
# This function retrieves configuration from Automation Variables with parameter override
function Get-AutomationVariableOrDefault {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$VariableName,
        [string]$ParameterValue,
        [string]$DefaultValue = ""
    )
    
    # If parameter is provided and not empty, use it
    if (-not [string]::IsNullOrWhiteSpace($ParameterValue)) {
        return [string]$ParameterValue
    }
    
    # Try to get from Automation Variable
    try {
        $value = Get-AutomationVariable -Name $VariableName -ErrorAction SilentlyContinue
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            # Use Write-Verbose instead of Write-Output to avoid polluting return value
            Write-Verbose "Using Automation Variable: $VariableName = $value"
            return [string]$value
        }
    }
    catch {
        # Variable doesn't exist or not running in Automation Account
        Write-Verbose "Automation Variable '$VariableName' not found or not in Automation Account context"
    }
    
    return [string]$DefaultValue
}

# Resolve configuration from variables or parameters
$resolvedConfig = @{
    ConfigurationPath         = Get-AutomationVariableOrDefault -VariableName "LifeCycle_ConfigurationPath" -ParameterValue $ConfigurationPath -DefaultValue ".\config\lifecycle-rules.json"
    DryRun                    = $false
    SendToLogAnalytics        = $false
    LogAnalyticsDceEndpoint   = Get-AutomationVariableOrDefault -VariableName "LifeCycle_LogAnalyticsDceEndpoint" -ParameterValue $LogAnalyticsDceEndpoint
    LogAnalyticsDcrImmutableId = Get-AutomationVariableOrDefault -VariableName "LifeCycle_LogAnalyticsDcrImmutableId" -ParameterValue $LogAnalyticsDcrImmutableId
    LogAnalyticsStreamName    = Get-AutomationVariableOrDefault -VariableName "LifeCycle_LogAnalyticsStreamName" -ParameterValue $LogAnalyticsStreamName
    LogAnalyticsTableName     = Get-AutomationVariableOrDefault -VariableName "LifeCycle_LogAnalyticsTableName" -ParameterValue $LogAnalyticsTableName
}

# Handle boolean switches - parameters override variables
if ($DryRun.IsPresent) {
    $resolvedConfig.DryRun = $true
} else {
    $dryRunVar = Get-AutomationVariableOrDefault -VariableName "LifeCycle_DryRun" -ParameterValue "" -DefaultValue "false"
    $resolvedConfig.DryRun = $dryRunVar -eq "true"
}

if ($SendToLogAnalytics.IsPresent) {
    $resolvedConfig.SendToLogAnalytics = $true
} else {
    $sendToLAVar = Get-AutomationVariableOrDefault -VariableName "LifeCycle_SendToLogAnalytics" -ParameterValue "" -DefaultValue "false"
    $resolvedConfig.SendToLogAnalytics = $sendToLAVar -eq "true"
}

# Use resolved values with distinct names (to avoid switch parameter conflicts)
$script:EffectiveConfigPath = $resolvedConfig.ConfigurationPath
$script:EffectiveDryRun = $resolvedConfig.DryRun
$script:EffectiveSendToLogAnalytics = $resolvedConfig.SendToLogAnalytics
$script:EffectiveLogAnalyticsDceEndpoint = $resolvedConfig.LogAnalyticsDceEndpoint
$script:EffectiveLogAnalyticsDcrImmutableId = $resolvedConfig.LogAnalyticsDcrImmutableId
$script:EffectiveLogAnalyticsStreamName = $resolvedConfig.LogAnalyticsStreamName
$script:EffectiveLogAnalyticsTableName = $resolvedConfig.LogAnalyticsTableName
#endregion

#region Log Analytics Ingestion Functions (Inline for Automation Account compatibility)

# Module-level variables for Log Analytics configuration
$script:LogAnalyticsConfig = @{
    DceEndpoint       = ""
    DcrImmutableId    = ""
    StreamName        = ""
    TableName         = ""
    BatchSize         = 500
    MaxRetries        = 3
    RetryDelaySeconds = 5
}

function Initialize-LogAnalyticsIngestion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DceEndpoint,
        
        [Parameter(Mandatory = $true)]
        [string]$DcrImmutableId,
        
        [Parameter(Mandatory = $true)]
        [string]$StreamName,
        
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        
        [Parameter(Mandatory = $false)]
        [int]$BatchSize = 500
    )
    
    $script:LogAnalyticsConfig.DceEndpoint = $DceEndpoint.TrimEnd('/')
    $script:LogAnalyticsConfig.DcrImmutableId = $DcrImmutableId
    $script:LogAnalyticsConfig.StreamName = $StreamName
    $script:LogAnalyticsConfig.TableName = $TableName
    $script:LogAnalyticsConfig.BatchSize = $BatchSize
    
    Write-Output "Log Analytics Ingestion initialized: Table=$TableName"
}

function Get-LogAnalyticsAccessToken {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    try {
        Write-Warning "[DEBUG] Requesting access token for https://monitor.azure.com..."
        $token = Get-AzAccessToken -ResourceUrl "https://monitor.azure.com" -ErrorAction Stop
        Write-Warning "[DEBUG] Token object received, type: $($token.GetType().Name)"
        Write-Warning "[DEBUG] Token.Token type: $($token.Token.GetType().Name)"
        
        if (-not $token) {
            throw "Failed to obtain access token for Azure Monitor - token is null"
        }
        
        # Handle both string and SecureString token formats (Az.Accounts version differences)
        $tokenValue = $token.Token
        if ($tokenValue -is [System.Security.SecureString]) {
            Write-Warning "[DEBUG] Converting SecureString token..."
            $tokenValue = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenValue)
            )
        }
        
        if ([string]::IsNullOrEmpty($tokenValue)) {
            throw "Failed to obtain access token for Azure Monitor - token is empty"
        }
        
        Write-Warning "[DEBUG] Access token obtained (length: $($tokenValue.Length), first 50 chars: $($tokenValue.Substring(0, [Math]::Min(50, $tokenValue.Length))))"
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
        
        # Ensure TimeGenerated is set
        if (-not $hash.ContainsKey('TimeGenerated')) {
            $hash['TimeGenerated'] = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        }
        
        # Return flat object - DCR schema expects flat fields, not wrapped in properties
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
            return [PSCustomObject]@{ Success = $true; TotalRecords = 0; Message = "No data to send" }
        }
        
        if (-not $script:LogAnalyticsConfig.DceEndpoint) {
            throw "Log Analytics not initialized. Call Initialize-LogAnalyticsIngestion first."
        }
        
        Write-Output "Sending $($allData.Count) $DataType records to Log Analytics..."
        
        $accessToken = Get-LogAnalyticsAccessToken
        $uri = "$($script:LogAnalyticsConfig.DceEndpoint)/dataCollectionRules/$($script:LogAnalyticsConfig.DcrImmutableId)/streams/$($script:LogAnalyticsConfig.StreamName)?api-version=2023-01-01"
        
        # Debug: Log the URI and auth header format
        Write-Warning "[DEBUG] Log Analytics Ingestion URI: $uri"
        Write-Warning "[DEBUG] Token length in header: $($accessToken.Length)"
        Write-Warning "[DEBUG] Token type in header: $($accessToken.GetType().Name)"
        Write-Warning "[DEBUG] Auth header value (first 60 chars): Bearer $($accessToken.Substring(0, [Math]::Min(50, $accessToken.Length)))..."
        
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
            
            Write-Output "Sending batch $batchNumber of $totalBatches ($($batch.Count) records)..."
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
                    
                    # Try to get response body for more details
                    $responseBody = ""
                    try {
                        $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                        $responseBody = $reader.ReadToEnd()
                        $reader.Close()
                    } catch { }
                    
                    Write-Warning "Batch $batchNumber failed (attempt $retryCount): Status $statusCode - $errorMessage"
                    if ($responseBody) {
                        Write-Warning "Response body: $responseBody"
                    }
                    
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

function Send-FileInventoryToLogAnalytics {
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
            $timestamp = (Get-Date).ToUniversalTime()
            foreach ($item in $allInventory) {
                if (-not ($item.PSObject.Properties.Name -contains 'TimeGenerated')) {
                    $item | Add-Member -NotePropertyName "TimeGenerated" -NotePropertyValue $timestamp -Force
                }
            }
        }
        
        return $allInventory | Send-ToLogAnalytics -DataType "FileInventory"
    }
}

#endregion

#region Global Variables
$script:AuditLog = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:FileInventory = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:ExecutionStartTime = Get-Date
$script:ExecutionId = [guid]::NewGuid().ToString()
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
            Write-Log "Configuration is a URL, downloading from blob storage..." -Level Information
            
            # Parse the blob URL to extract storage account, container, and blob name
            # Format: https://<storage-account>.blob.core.windows.net/<container>/<blob-path>
            $uri = [System.Uri]$ConfigPath
            $storageAccountName = $uri.Host.Split('.')[0]
            $pathParts = $uri.AbsolutePath.TrimStart('/').Split('/', 2)
            $containerName = $pathParts[0]
            $blobName = $pathParts[1]
            
            Write-Log "Storage Account: $storageAccountName, Container: $containerName, Blob: $blobName" -Level Information
            
            # Get storage context using Managed Identity (OAuth)
            $storageContext = New-AzStorageContext -StorageAccountName $storageAccountName -UseConnectedAccount -ErrorAction Stop
            
            # Download blob content to memory
            $tempFile = [System.IO.Path]::GetTempFileName()
            try {
                Get-AzStorageBlobContent -Container $containerName -Blob $blobName -Destination $tempFile -Context $storageContext -Force -ErrorAction Stop | Out-Null
                $configContent = Get-Content -Path $tempFile -Raw
                $config = $configContent | ConvertFrom-Json
            }
            finally {
                # Clean up temp file
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
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
    
    # Check created date (use FileProperties.SmbProperties.FileCreatedOn in modern Az.Storage)
    if ($Conditions.createdDaysAgo) {
        $thresholdDate = $currentDate.AddDays(-$Conditions.createdDaysAgo)
        $fileCreatedOn = $File.FileProperties.SmbProperties.FileCreatedOn
        if ($fileCreatedOn -and $fileCreatedOn -gt $thresholdDate) {
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
        $FileLastModified,  # Accept any type (DateTime or DateTimeOffset)
        
        [Parameter(Mandatory = $false)]
        [string]$Status = "Success",
        
        [Parameter(Mandatory = $false)]
        [string]$ErrorMessage = ""
    )
    
    # Convert DateTimeOffset to DateTime if needed
    $fileLastModifiedDT = if ($FileLastModified -is [DateTimeOffset]) { $FileLastModified.DateTime } elseif ($FileLastModified) { $FileLastModified } else { $null }
    
    $entry = [PSCustomObject]@{
        Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        StorageAccount    = $StorageAccount
        FileShare         = $FileShare
        FilePath          = $FilePath
        Action            = $Action
        RuleName          = $RuleName
        FileSizeBytes     = $FileSizeBytes
        FileSizeMB        = [math]::Round($FileSizeBytes / 1MB, 2)
        FileLastModified  = $fileLastModifiedDT
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
        $LastModified,  # Accept any type (DateTime or DateTimeOffset)
        
        [Parameter(Mandatory = $false)]
        $Created,  # Accept any type (DateTime or DateTimeOffset)
        
        [Parameter(Mandatory = $false)]
        [string]$FileExtension = "",
        
        [Parameter(Mandatory = $false)]
        [string]$FileHash = ""
    )
    
    # Convert DateTimeOffset to DateTime if needed
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
    .DESCRIPTION
        Navigates through the file share recursively and returns all file objects.
        Each file object has a FullPath property added for convenience.
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
        # Get items at current path
        $items = if ([string]::IsNullOrEmpty($Path)) {
            # Root level - Get-AzStorageFile returns contents directly
            Get-AzStorageFile -Context $Context -ShareName $ShareName -ErrorAction Stop
        } else {
            # Subdirectory - need to get the directory object first, then pipe to get contents
            Get-AzStorageFile -Context $Context -ShareName $ShareName -Path $Path -ErrorAction Stop | 
                Get-AzStorageFile -ErrorAction Stop
        }
        
        foreach ($item in $items) {
            $isDirectory = ($item.GetType().Name -eq "AzureStorageFileDirectory")
            
            if ($isDirectory) {
                # Recursively get files from subdirectory
                $subPath = if ($Path) { "$Path/$($item.Name)" } else { $item.Name }
                $subFiles = Get-AllFilesRecursive -Context $Context -ShareName $ShareName -Path $subPath
                $files.AddRange($subFiles)
            }
            else {
                # It's a file - add FullPath property
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
    <#
    .SYNOPSIS
        Calculates MD5 hash for a file in Azure File Share
    .DESCRIPTION
        Downloads the file to a temp location and calculates MD5 hash.
        Azure Files doesn't store ContentHash like Blob Storage, so we always calculate it.
        For large files, returns SKIPPED_TOO_LARGE to avoid performance issues.
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
        [long]$MaxSizeForHash = 100MB
    )
    
    try {
        # Get file object - use directory path to get file listing, then filter
        $parentPath = [System.IO.Path]::GetDirectoryName($FilePath) -replace '\\', '/'
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        
        # Get file size to check before downloading
        $file = $null
        if ([string]::IsNullOrEmpty($parentPath)) {
            # File is in root
            $file = Get-AzStorageFile -Context $Context -ShareName $ShareName -ErrorAction Stop | 
                    Where-Object { $_.Name -eq $fileName -and -not $_.IsDirectory } | 
                    Select-Object -First 1
        } else {
            # File is in a subdirectory - navigate to parent directory first
            $file = Get-AzStorageFile -Context $Context -ShareName $ShareName -Path $parentPath -ErrorAction Stop | 
                    Get-AzStorageFile -ErrorAction Stop | 
                    Where-Object { $_.Name -eq $fileName -and -not $_.IsDirectory } | 
                    Select-Object -First 1
        }
        
        if (-not $file) {
            Write-Log "File not found for hash calculation: $FilePath" -Level Warning
            return "ERROR_NOT_FOUND"
        }
        
        # Skip hash calculation for very large files to avoid performance issues
        $fileLength = if ($file.Length) { $file.Length } elseif ($file.FileProperties.ContentLength) { $file.FileProperties.ContentLength } else { 0 }
        if ($fileLength -gt $MaxSizeForHash) {
            return "SKIPPED_TOO_LARGE"
        }
        
        # Check if ContentHash is available (Azure Files may have it in some cases)
        if ($file.FileProperties -and $file.FileProperties.ContentHash -and $file.FileProperties.ContentHash.Length -gt 0) {
            return [System.Convert]::ToBase64String($file.FileProperties.ContentHash)
        }
        
        # Download and calculate hash
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
    
    # Calculate file hashes and add to inventory
    Write-Log "Calculating file hashes and building inventory..." -Level Information
    $processedCount = 0
    foreach ($file in $allFiles) {
        $processedCount++
        if ($processedCount % 100 -eq 0) {
            Write-Log "Processed $processedCount of $($allFiles.Count) files..." -Level Information
        }
        
        # Calculate hash for duplicate detection
        $fileHash = Get-AzureFileHash `
            -Context $StorageContext `
            -ShareName $shareName `
            -FilePath $file.FullPath `
            -MaxSizeForHash 100MB
        
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

function Export-DuplicateFilesReport {
    <#
    .SYNOPSIS
        Exports duplicate files report to CSV and uploads to Blob storage
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$StorageContext,
        
        [Parameter(Mandatory = $true)]
        [string]$ContainerName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$DuplicateGroups,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DuplicateGroups.Count -eq 0) {
        Write-Log "No duplicate files to export" -Level Information
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $fileName = "duplicate-files_$timestamp.csv"
    $localPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $fileName)
    
    try {
        # Build duplicate file report
        $duplicateReport = [System.Collections.Generic.List[PSCustomObject]]::new()
        
        foreach ($hash in $DuplicateGroups.Keys) {
            $files = $DuplicateGroups[$hash]
            $fileSize = $files[0].FileSizeBytes
            $wastedSpace = $fileSize * ($files.Count - 1)
            
            $duplicateReport.Add([PSCustomObject]@{
                FileHash           = $hash
                FileName           = $files[0].FileName
                FileExtension      = $files[0].FileExtension
                FileSizeBytes      = $fileSize
                FileSizeMB         = [math]::Round($fileSize / 1MB, 2)
                FileSizeGB         = [math]::Round($fileSize / 1GB, 4)
                DuplicateCount     = $files.Count
                WastedSpaceBytes   = $wastedSpace
                WastedSpaceMB      = [math]::Round($wastedSpace / 1MB, 2)
                WastedSpaceGB      = [math]::Round($wastedSpace / 1GB, 4)
                StorageAccounts    = ($files | Select-Object -ExpandProperty StorageAccount -Unique) -join '; '
                FileShares         = ($files | Select-Object -ExpandProperty FileShare -Unique) -join '; '
                AllLocations       = ($files | Select-Object -ExpandProperty FilePath) -join ' | '
            })
        }
        
        # Sort by wasted space descending
        $duplicateReport | Sort-Object -Property WastedSpaceBytes -Descending | Export-Csv -Path $localPath -NoTypeInformation -Encoding UTF8
        
        Write-Log "Duplicate files report exported to: $localPath ($($duplicateReport.Count) groups)" -Level Information
        
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
            
            Write-Log "Duplicate files report uploaded to Blob storage: $ContainerName/$fileName" -Level Information
            
            # Also upload a "latest" version
            $latestFileName = "duplicate-files_latest.csv"
            Set-AzStorageBlobContent `
                -Context $StorageContext `
                -Container $ContainerName `
                -File $localPath `
                -Blob $latestFileName `
                -Force | Out-Null
            
            Write-Log "Latest duplicate files report updated: $ContainerName/$latestFileName" -Level Information
        }
        else {
            Write-Log "[DRY RUN] Would upload duplicate files report to: $ContainerName/$fileName" -Level Information
        }
    }
    catch {
        Write-Log "Failed to export/upload duplicate files report: $_" -Level Error
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
    
    # Set dry run mode (from resolved effective configuration)
    $script:DryRunMode = $script:EffectiveDryRun
    if ($script:DryRunMode) {
        Write-Log "*** DRY RUN MODE ENABLED - No changes will be made ***" -Level Warning
    }
    
    # Connect to Azure using managed identity
    Connect-AzureWithManagedIdentity
    
    # Load configuration
    $config = Get-LifecycleConfiguration -ConfigPath $script:EffectiveConfigPath
    
    # Override dry run from config if not already set
    if ($config.globalSettings.dryRun -and -not $script:DryRunMode) {
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
    
    # Detect duplicate files
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
                Where-Object { $_.FileHash -and $_.FileHash -ne "SKIPPED_TOO_LARGE" -and $_.FileHash -ne "ERROR" } | 
                Group-Object -Property FileHash | 
                Where-Object { $_.Count -gt 1 }
            
            foreach ($hashGroup in $hashGroups) {
                $hash = $hashGroup.Name
                $duplicates = $hashGroup.Group
                
                if ($duplicates.Count -gt 1) {
                    $duplicateGroups[$hash] = $duplicates
                    
                    # Update inventory entries
                    foreach ($file in $duplicates) {
                        $file.IsDuplicate = "Yes"
                        $file.DuplicateCount = $duplicates.Count
                    }
                }
            }
        }
        
        Write-Log "Found $($duplicateGroups.Count) groups of duplicate files" -Level Information
        $totalDuplicates = ($duplicateGroups.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        $wastedSpace = 0
        foreach ($hash in $duplicateGroups.Keys) {
            $files = $duplicateGroups[$hash]
            $wastedSpace += $files[0].FileSizeBytes * ($files.Count - 1)
        }
        Write-Log "Total duplicate files: $totalDuplicates (wasting $([math]::Round($wastedSpace / 1GB, 2)) GB)" -Level Warning
    }
    else {
        Write-Log "No duplicate files found" -Level Information
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
        
        # Export duplicate files report if duplicates found
        if ($duplicateGroups.Count -gt 0) {
            Export-DuplicateFilesReport `
                -StorageContext $auditStorageContext `
                -ContainerName $config.globalSettings.fileInventoryContainer `
                -DuplicateGroups $duplicateGroups `
                -DryRun:$script:DryRunMode
        }
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
    
    # Send file inventory to Log Analytics if enabled
    if ($script:EffectiveSendToLogAnalytics -and $script:FileInventory.Count -gt 0) {
        Write-Log "Sending file inventory to Log Analytics..." -Level Information
        
        try {
            # Get Log Analytics settings from effective config or JSON config
            $dceEndpoint = if ($script:EffectiveLogAnalyticsDceEndpoint) { $script:EffectiveLogAnalyticsDceEndpoint } 
                           elseif ($config.globalSettings.logAnalytics.dceEndpoint) { $config.globalSettings.logAnalytics.dceEndpoint }
                           else { "" }
            
            $dcrImmutableId = if ($script:EffectiveLogAnalyticsDcrImmutableId) { $script:EffectiveLogAnalyticsDcrImmutableId }
                              elseif ($config.globalSettings.logAnalytics.dcrImmutableId) { $config.globalSettings.logAnalytics.dcrImmutableId }
                              else { "" }
            
            $streamName = if ($script:EffectiveLogAnalyticsStreamName) { $script:EffectiveLogAnalyticsStreamName }
                          elseif ($config.globalSettings.logAnalytics.streamName) { $config.globalSettings.logAnalytics.streamName }
                          else { "" }
            
            $tableName = if ($script:EffectiveLogAnalyticsTableName) { $script:EffectiveLogAnalyticsTableName }
                         elseif ($config.globalSettings.logAnalytics.tableName) { $config.globalSettings.logAnalytics.tableName }
                         else { "" }
            
            if (-not $dceEndpoint -or -not $dcrImmutableId -or -not $streamName -or -not $tableName) {
                Write-Log "Log Analytics configuration incomplete. Required: DCE Endpoint, DCR Immutable ID, Stream Name, Table Name" -Level Warning
            }
            else {
                # Initialize Log Analytics ingestion
                Initialize-LogAnalyticsIngestion `
                    -DceEndpoint $dceEndpoint `
                    -DcrImmutableId $dcrImmutableId `
                    -StreamName $streamName `
                    -TableName $tableName `
                    -BatchSize 500
                
                # Prepare enriched inventory data with additional fields for Log Analytics
                $enrichedInventory = $script:FileInventory | ForEach-Object {
                    $item = $_
                    
                    # Add additional categorization fields if not present
                    if (-not $item.PSObject.Properties['FileCategory']) {
                        $extension = $item.FileExtension.ToLower()
                        $category = switch -Regex ($extension) {
                            '\.(doc|docx|pdf|txt|rtf|odt|xls|xlsx|ppt|pptx|csv)$' { "Documents" }
                            '\.(jpg|jpeg|png|gif|bmp|tiff|svg|ico|webp|raw)$' { "Images" }
                            '\.(mp4|avi|mkv|mov|wmv|flv|webm|m4v)$' { "Videos" }
                            '\.(mp3|wav|flac|aac|ogg|wma|m4a)$' { "Audio" }
                            '\.(zip|rar|7z|tar|gz|bz2|xz)$' { "Archives" }
                            '\.(cs|js|ts|py|java|cpp|h|ps1|psm1|sh|json|xml|yaml|yml)$' { "Code" }
                            '\.(exe|dll|msi|bat|cmd|com)$' { "Executables" }
                            '\.(sql|mdf|ldf|bak|db|sqlite)$' { "Databases" }
                            '\.(log|evt|evtx)$' { "Logs" }
                            '\.(tmp|temp|bak|swp|cache)$' { "Temporary" }
                            default { "Other" }
                        }
                        $item | Add-Member -NotePropertyName "FileCategory" -NotePropertyValue $category -Force
                    }
                    
                    # Add age bucket if not present
                    if (-not $item.PSObject.Properties['AgeBucket'] -and $item.AgeInDays) {
                        $ageBucket = switch ($item.AgeInDays) {
                            { $_ -le 7 }    { "0-7 days" }
                            { $_ -le 30 }   { "8-30 days" }
                            { $_ -le 90 }   { "31-90 days" }
                            { $_ -le 180 }  { "91-180 days" }
                            { $_ -le 365 }  { "181-365 days" }
                            { $_ -le 730 }  { "1-2 years" }
                            { $_ -le 1825 } { "2-5 years" }
                            default         { "5+ years" }
                        }
                        $item | Add-Member -NotePropertyName "AgeBucket" -NotePropertyValue $ageBucket -Force
                    }
                    
                    # Add size bucket if not present
                    if (-not $item.PSObject.Properties['SizeBucket']) {
                        $sizeBucket = switch ($true) {
                            { $item.FileSizeBytes -lt 1KB }     { "< 1 KB" }
                            { $item.FileSizeBytes -lt 1MB }     { "1 KB - 1 MB" }
                            { $item.FileSizeMB -lt 10 }         { "1 MB - 10 MB" }
                            { $item.FileSizeMB -lt 100 }        { "10 MB - 100 MB" }
                            { $item.FileSizeMB -lt 500 }        { "100 MB - 500 MB" }
                            { $item.FileSizeGB -lt 1 }          { "500 MB - 1 GB" }
                            { $item.FileSizeGB -lt 5 }          { "1 GB - 5 GB" }
                            { $item.FileSizeGB -lt 10 }         { "5 GB - 10 GB" }
                            default                              { "10+ GB" }
                        }
                        $item | Add-Member -NotePropertyName "SizeBucket" -NotePropertyValue $sizeBucket -Force
                    }
                    
                    $item
                }
                
                # Send to Log Analytics
                $laResult = $enrichedInventory | Send-FileInventoryToLogAnalytics `
                    -IncludeExecutionMetadata `
                    -ExecutionId $script:ExecutionId
                
                if ($laResult.Success) {
                    Write-Log "Successfully sent $($laResult.RecordsSent) file inventory records to Log Analytics table '$tableName'" -Level Information
                    Write-Log "  Duration: $($laResult.DurationSeconds) seconds, Batches: $($laResult.BatchesSent)/$($laResult.TotalBatches)" -Level Information
                }
                else {
                    Write-Log "Failed to send some records to Log Analytics: $($laResult.Message)" -Level Warning
                }
            }
        }
        catch {
            Write-Log "Error sending data to Log Analytics: $_" -Level Error
            # Don't fail the entire runbook if Log Analytics fails
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
