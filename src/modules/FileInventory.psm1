<#
.SYNOPSIS
    File Inventory Module for Azure File Storage Lifecycle Management
    
.DESCRIPTION
    Provides functions for creating and managing file inventory reports
    
.NOTES
    Version: 1.0.0
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
    'Export-DuplicateFilesReport'
)
