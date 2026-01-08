<#
.SYNOPSIS
    File Inventory Module for Azure File Storage Lifecycle Management
    
.DESCRIPTION
    Provides functions for creating and managing file inventory reports,
    including Log Analytics ingestion capabilities using DCR/DCE with Managed Identity.
    
.NOTES
    Version: 1.1.0
    Features:
    - File inventory entry creation and management
    - CSV export with size-based sorting
    - Duplicate file detection
    - Directory tree analysis
    - Log Analytics streaming via Logs Ingestion API
#>

function New-FileInventoryEntry {
    <#
    .SYNOPSIS
        Creates a new file inventory entry object
        
    .PARAMETER StorageAccount
        Name of the storage account
        
    .PARAMETER FileShare
        Name of the file share
        
    .PARAMETER FilePath
        Full path to the file
        
    .PARAMETER FileSizeBytes
        Size of the file in bytes
        
    .PARAMETER LastModified
        Last modified timestamp
        
    .PARAMETER Created
        Creation timestamp
        
    .PARAMETER ContentType
        Content type of the file
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
        [long]$FileSizeBytes,
        
        [Parameter(Mandatory = $false)]
        [datetime]$LastModified,
        
        [Parameter(Mandatory = $false)]
        [datetime]$Created,
        
        [Parameter(Mandatory = $false)]
        [string]$ContentType = "",
        
        [Parameter(Mandatory = $false)]
        [string]$FileHash = "",
        
        [Parameter(Mandatory = $false)]
        [bool]$IsDuplicate = $false,
        
        [Parameter(Mandatory = $false)]
        [int]$DuplicateCount = 0
    )
    
    $fileName = [System.IO.Path]::GetFileName($FilePath)
    $extension = [System.IO.Path]::GetExtension($FilePath)
    $directory = [System.IO.Path]::GetDirectoryName($FilePath) -replace '\\', '/'
    
    # Determine file category based on extension
    $category = Get-FileCategoryFromExtension -Extension $extension
    
    return [PSCustomObject]@{
        StorageAccount       = $StorageAccount
        FileShare            = $FileShare
        Directory            = $directory
        FilePath             = $FilePath
        FileName             = $fileName
        FileExtension        = $extension.ToLower()
        FileCategory         = $category
        FileSizeBytes        = $FileSizeBytes
        FileSizeKB           = [math]::Round($FileSizeBytes / 1KB, 2)
        FileSizeMB           = [math]::Round($FileSizeBytes / 1MB, 2)
        FileSizeGB           = [math]::Round($FileSizeBytes / 1GB, 4)
        FileSizeTB           = [math]::Round($FileSizeBytes / 1TB, 6)
        LastModified         = $LastModified
        LastModifiedDate     = if ($LastModified) { $LastModified.ToString("yyyy-MM-dd") } else { $null }
        Created              = $Created
        CreatedDate          = if ($Created) { $Created.ToString("yyyy-MM-dd") } else { $null }
        AgeInDays            = if ($LastModified) { [math]::Round((Get-Date).Subtract($LastModified).TotalDays, 0) } else { $null }
        AgeBucket            = Get-AgeBucket -AgeInDays $(if ($LastModified) { [math]::Round((Get-Date).Subtract($LastModified).TotalDays, 0) } else { 0 })
        SizeBucket           = Get-SizeBucket -SizeInBytes $FileSizeBytes
        ContentType          = $ContentType
        FileHash             = $FileHash
        IsDuplicate          = if ($IsDuplicate) { "Yes" } else { "No" }
        DuplicateCount       = $DuplicateCount
        ScanTimestamp        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ScanTimestampUTC     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    }
}

function Get-FileCategoryFromExtension {
    <#
    .SYNOPSIS
        Determines file category based on extension
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Extension
    )
    
    $extension = $Extension.ToLower()
    
    $categories = @{
        "Documents"    = @(".doc", ".docx", ".pdf", ".txt", ".rtf", ".odt", ".xls", ".xlsx", ".ppt", ".pptx", ".csv")
        "Images"       = @(".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".ico", ".webp", ".raw")
        "Videos"       = @(".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".m4v")
        "Audio"        = @(".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a")
        "Archives"     = @(".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz")
        "Code"         = @(".cs", ".js", ".ts", ".py", ".java", ".cpp", ".h", ".ps1", ".psm1", ".sh", ".json", ".xml", ".yaml", ".yml")
        "Executables"  = @(".exe", ".dll", ".msi", ".bat", ".cmd", ".com")
        "Databases"    = @(".sql", ".mdf", ".ldf", ".bak", ".db", ".sqlite")
        "Logs"         = @(".log", ".evt", ".evtx")
        "Temporary"    = @(".tmp", ".temp", ".bak", ".swp", ".cache")
    }
    
    foreach ($category in $categories.Keys) {
        if ($extension -in $categories[$category]) {
            return $category
        }
    }
    
    return "Other"
}

function Get-AgeBucket {
    <#
    .SYNOPSIS
        Determines age bucket for a file
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
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
    <#
    .SYNOPSIS
        Determines size bucket for a file
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [long]$SizeInBytes
    )
    
    $sizeInMB = $SizeInBytes / 1MB
    $sizeInGB = $SizeInBytes / 1GB
    
    switch ($true) {
        { $SizeInBytes -lt 1KB }     { return "< 1 KB" }
        { $SizeInBytes -lt 1MB }     { return "1 KB - 1 MB" }
        { $sizeInMB -lt 10 }         { return "1 MB - 10 MB" }
        { $sizeInMB -lt 100 }        { return "10 MB - 100 MB" }
        { $sizeInMB -lt 500 }        { return "100 MB - 500 MB" }
        { $sizeInGB -lt 1 }          { return "500 MB - 1 GB" }
        { $sizeInGB -lt 5 }          { return "1 GB - 5 GB" }
        { $sizeInGB -lt 10 }         { return "5 GB - 10 GB" }
        default                       { return "10+ GB" }
    }
}

function Export-FileInventoryToCsv {
    <#
    .SYNOPSIS
        Exports file inventory to CSV sorted by size
        
    .PARAMETER FileInventory
        Collection of file inventory entries
        
    .PARAMETER OutputPath
        Path to save the CSV file
        
    .PARAMETER SortOrder
        Sort order: Descending (largest first) or Ascending (smallest first)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$FileInventory,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Descending", "Ascending")]
        [string]$SortOrder = "Descending"
    )
    
    begin {
        $allEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    
    process {
        foreach ($entry in $FileInventory) {
            $allEntries.Add($entry)
        }
    }
    
    end {
        if ($allEntries.Count -eq 0) {
            Write-Verbose "No file inventory entries to export"
            return
        }
        
        # Sort by file size
        $sortedEntries = if ($SortOrder -eq "Descending") {
            $allEntries | Sort-Object -Property FileSizeBytes -Descending
        }
        else {
            $allEntries | Sort-Object -Property FileSizeBytes
        }
        
        # Add rank column
        $rank = 1
        $rankedEntries = $sortedEntries | ForEach-Object {
            $_ | Add-Member -NotePropertyName "SizeRank" -NotePropertyValue $rank -Force
            $rank++
            $_
        }
        
        $rankedEntries | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Verbose "Exported $($allEntries.Count) file inventory entries to: $OutputPath (sorted by size $SortOrder)"
    }
}

function Get-FileInventorySummary {
    <#
    .SYNOPSIS
        Generates a summary of file inventory
        
    .PARAMETER FileInventory
        Collection of file inventory entries
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$FileInventory
    )
    
    $totalSize = ($FileInventory | Measure-Object -Property FileSizeBytes -Sum).Sum
    
    # Get top 10 largest files
    $top10Files = $FileInventory | Sort-Object -Property FileSizeBytes -Descending | Select-Object -First 10
    
    # Get size by category
    $sizeByCategory = $FileInventory | Group-Object -Property FileCategory | ForEach-Object {
        [PSCustomObject]@{
            Category    = $_.Name
            FileCount   = $_.Count
            TotalSizeGB = [math]::Round(($_.Group | Measure-Object -Property FileSizeBytes -Sum).Sum / 1GB, 2)
        }
    } | Sort-Object -Property TotalSizeGB -Descending
    
    # Get size by storage account
    $sizeByAccount = $FileInventory | Group-Object -Property StorageAccount | ForEach-Object {
        [PSCustomObject]@{
            StorageAccount = $_.Name
            FileCount      = $_.Count
            TotalSizeGB    = [math]::Round(($_.Group | Measure-Object -Property FileSizeBytes -Sum).Sum / 1GB, 2)
        }
    } | Sort-Object -Property TotalSizeGB -Descending
    
    return [PSCustomObject]@{
        TotalFiles              = $FileInventory.Count
        TotalSizeBytes          = $totalSize
        TotalSizeGB             = [math]::Round($totalSize / 1GB, 2)
        TotalSizeTB             = [math]::Round($totalSize / 1TB, 4)
        AverageFileSizeMB       = [math]::Round(($totalSize / $FileInventory.Count) / 1MB, 2)
        UniqueStorageAccounts   = ($FileInventory | Select-Object -ExpandProperty StorageAccount -Unique).Count
        UniqueFileShares        = ($FileInventory | Select-Object -ExpandProperty FileShare -Unique).Count
        UniqueExtensions        = ($FileInventory | Select-Object -ExpandProperty FileExtension -Unique).Count
        Top10LargestFiles       = $top10Files
        SizeByCategory          = $sizeByCategory
        SizeByStorageAccount    = $sizeByAccount
        GeneratedAt             = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Get-DirectoryTreeData {
    <#
    .SYNOPSIS
        Generates hierarchical directory tree data for TreeSize-like visualization
        
    .PARAMETER FileInventory
        Collection of file inventory entries
        
    .PARAMETER MaxDepth
        Maximum depth to include in tree
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$FileInventory,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 5
    )
    
    $treeData = [System.Collections.Generic.List[PSCustomObject]]::new()
    
    # Group by path hierarchy
    $grouped = $FileInventory | Group-Object -Property { 
        $pathParts = $_.FilePath -split '[/\\]'
        $depth = [Math]::Min($pathParts.Count - 1, $MaxDepth)
        ($pathParts[0..$depth] -join '/') -replace '/[^/]+$', ''
    }
    
    foreach ($group in $grouped) {
        $pathParts = $group.Name -split '[/\\]'
        
        $entry = [PSCustomObject]@{
            Path            = $group.Name
            Name            = $pathParts[-1]
            Depth           = $pathParts.Count
            FileCount       = $group.Count
            TotalSizeBytes  = ($group.Group | Measure-Object -Property FileSizeBytes -Sum).Sum
            TotalSizeGB     = [math]::Round(($group.Group | Measure-Object -Property FileSizeBytes -Sum).Sum / 1GB, 2)
            PercentOfTotal  = 0  # Will be calculated after
            ParentPath      = if ($pathParts.Count -gt 1) { ($pathParts[0..($pathParts.Count - 2)] -join '/') } else { $null }
        }
        
        $treeData.Add($entry)
    }
    
    # Calculate percentage of total
    $totalSize = ($treeData | Measure-Object -Property TotalSizeBytes -Sum).Sum
    if ($totalSize -gt 0) {
        foreach ($entry in $treeData) {
            $entry.PercentOfTotal = [math]::Round(($entry.TotalSizeBytes / $totalSize) * 100, 2)
        }
    }
    
    return $treeData | Sort-Object -Property TotalSizeBytes -Descending
}

function Find-DuplicateFiles {
    <#
    .SYNOPSIS
        Identifies duplicate files based on size and content hash
        
    .DESCRIPTION
        Analyzes file inventory to find duplicates. Files are considered duplicates if they have:
        - Same file size (quick check)
        - Same content hash (computed for files with matching sizes)
        
    .PARAMETER FileInventory
        Collection of file inventory entries
        
    .PARAMETER UpdateInventory
        If specified, updates the IsDuplicate and DuplicateCount properties in the inventory
        
    .OUTPUTS
        Returns a hashtable with hash as key and array of duplicate file entries as value
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$FileInventory,
        
        [Parameter(Mandatory = $false)]
        [switch]$UpdateInventory
    )
    
    Write-Verbose "Analyzing $($FileInventory.Count) files for duplicates..."
    
    # Group files by size first (quick pre-filter)
    $filesBySize = $FileInventory | Group-Object -Property FileSizeBytes | Where-Object { $_.Count -gt 1 }
    
    if ($filesBySize.Count -eq 0) {
        Write-Verbose "No files with matching sizes found"
        return @{}
    }
    
    Write-Verbose "Found $($filesBySize.Count) size groups with potential duplicates"
    
    # For files with matching sizes, group by hash
    $duplicateGroups = @{}
    
    foreach ($sizeGroup in $filesBySize) {
        $filesInGroup = $sizeGroup.Group
        
        # Group by hash within this size group
        $hashGroups = $filesInGroup | 
            Where-Object { $_.FileHash } | 
            Group-Object -Property FileHash | 
            Where-Object { $_.Count -gt 1 }
        
        foreach ($hashGroup in $hashGroups) {
            $hash = $hashGroup.Name
            $duplicates = $hashGroup.Group
            
            if ($hash -and $duplicates.Count -gt 1) {
                $duplicateGroups[$hash] = $duplicates
                
                # Update inventory if requested
                if ($UpdateInventory) {
                    foreach ($file in $duplicates) {
                        $file.IsDuplicate = "Yes"
                        $file.DuplicateCount = $duplicates.Count
                    }
                }
            }
        }
    }
    
    Write-Verbose "Found $($duplicateGroups.Count) groups of duplicate files"
    
    return $duplicateGroups
}

function Get-DuplicateFilesSummary {
    <#
    .SYNOPSIS
        Generates a summary report of duplicate files
        
    .PARAMETER DuplicateGroups
        Hashtable of duplicate file groups from Find-DuplicateFiles
        
    .OUTPUTS
        Returns a summary object with duplicate statistics
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$DuplicateGroups
    )
    
    $totalDuplicateFiles = 0
    $totalWastedSpace = 0
    $duplicateSummary = [System.Collections.Generic.List[PSCustomObject]]::new()
    
    foreach ($hash in $DuplicateGroups.Keys) {
        $files = $DuplicateGroups[$hash]
        $fileCount = $files.Count
        $fileSize = $files[0].FileSizeBytes
        $wastedSpace = $fileSize * ($fileCount - 1)  # Space used by duplicates (keeping 1 original)
        
        $totalDuplicateFiles += $fileCount
        $totalWastedSpace += $wastedSpace
        
        $duplicateSummary.Add([PSCustomObject]@{
            FileHash           = $hash
            FileName           = $files[0].FileName
            FileExtension      = $files[0].FileExtension
            FileSizeBytes      = $fileSize
            FileSizeMB         = [math]::Round($fileSize / 1MB, 2)
            FileSizeGB         = [math]::Round($fileSize / 1GB, 4)
            DuplicateCount     = $fileCount
            WastedSpaceBytes   = $wastedSpace
            WastedSpaceMB      = [math]::Round($wastedSpace / 1MB, 2)
            WastedSpaceGB      = [math]::Round($wastedSpace / 1GB, 4)
            StorageAccounts    = ($files | Select-Object -ExpandProperty StorageAccount -Unique) -join '; '
            FileShares         = ($files | Select-Object -ExpandProperty FileShare -Unique) -join '; '
            Locations          = ($files | Select-Object -ExpandProperty FilePath) -join '; '
        })
    }
    
    return [PSCustomObject]@{
        TotalDuplicateGroups = $DuplicateGroups.Count
        TotalDuplicateFiles  = $totalDuplicateFiles
        TotalWastedSpaceBytes = $totalWastedSpace
        TotalWastedSpaceMB   = [math]::Round($totalWastedSpace / 1MB, 2)
        TotalWastedSpaceGB   = [math]::Round($totalWastedSpace / 1GB, 2)
        TotalWastedSpaceTB   = [math]::Round($totalWastedSpace / 1TB, 4)
        DuplicateDetails     = $duplicateSummary | Sort-Object -Property WastedSpaceBytes -Descending
        GeneratedAt          = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Export-DuplicateFilesReport {
    <#
    .SYNOPSIS
        Exports duplicate files report to CSV
        
    .PARAMETER DuplicateSummary
        Summary object from Get-DuplicateFilesSummary
        
    .PARAMETER OutputPath
        Path to save the CSV file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DuplicateSummary,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    if ($DuplicateSummary.DuplicateDetails.Count -eq 0) {
        Write-Verbose "No duplicate files to export"
        return
    }
    
    $DuplicateSummary.DuplicateDetails | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Verbose "Exported $($DuplicateSummary.DuplicateDetails.Count) duplicate file groups to: $OutputPath"
}

#region Log Analytics Ingestion Functions

# Module-level variables for Log Analytics configuration
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

#endregion

# Export functions
Export-ModuleMember -Function @(
    'New-FileInventoryEntry',
    'Get-FileCategoryFromExtension',
    'Get-AgeBucket',
    'Get-SizeBucket',
    'Export-FileInventoryToCsv',
    'Get-FileInventorySummary',
    'Get-DirectoryTreeData',
    'Find-DuplicateFiles',
    'Get-DuplicateFilesSummary',
    'Export-DuplicateFilesReport',
    'Initialize-LogAnalyticsIngestion',
    'Get-LogAnalyticsAccessToken',
    'Send-ToLogAnalytics',
    'ConvertTo-LogAnalyticsJson',
    'Send-FileInventoryToLogAnalytics',
    'Test-LogAnalyticsConnection'
)
