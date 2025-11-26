# Power BI Dashboard - Duplicate Files View

## Overview
The duplicate files detection feature identifies files with identical content across your Azure File Storage, helping you reclaim wasted storage space.

## Data Sources

### 1. File Inventory (file-inventory_latest.csv)
Contains all scanned files with duplicate detection information:

**Key Columns:**
- `StorageAccount` - Storage account name
- `FileShare` - File share name
- `FilePath` - Full path to file
- `FileName` - File name only
- `FileExtension` - File extension
- `FileSizeBytes` - File size in bytes
- `FileSizeMB` - File size in MB
- `FileSizeGB` - File size in GB
- `FileHash` - MD5 hash of file content
- `IsDuplicate` - "Yes" or "No"
- `DuplicateCount` - Number of copies of this file
- `LastModified` - Last modification date
- `AgeInDays` - Age in days
- `ScanTimestamp` - When the scan was performed

### 2. Duplicate Files Report (duplicate-files_latest.csv)
Summarized view of duplicate file groups:

**Key Columns:**
- `FileHash` - Unique hash identifying duplicate group
- `FileName` - Name of the duplicated file
- `FileExtension` - File extension
- `FileSizeBytes/MB/GB` - Size of individual file
- `DuplicateCount` - How many copies exist
- `WastedSpaceBytes/MB/GB` - Storage wasted by duplicates (size × (count - 1))
- `StorageAccounts` - Which storage accounts contain duplicates
- `FileShares` - Which file shares contain duplicates
- `AllLocations` - All file paths where duplicates exist (separated by |)

## Power BI Visualizations

### 1. Duplicate Files Summary Card
**Visual Type:** Card
**Measure:**
```DAX
Total Duplicate Files = 
COUNTROWS(
    FILTER('FileInventory', 'FileInventory'[IsDuplicate] = "Yes")
)

Wasted Space GB = 
SUMX(
    FILTER('FileInventory', 'FileInventory'[IsDuplicate] = "Yes"),
    'FileInventory'[FileSizeGB] * ('FileInventory'[DuplicateCount] - 1) / 'FileInventory'[DuplicateCount]
)

Duplicate Groups = 
DISTINCTCOUNT('DuplicateFilesReport'[FileHash])
```

### 2. Top Duplicate Files by Wasted Space
**Visual Type:** Bar Chart
**Axis:** FileName
**Value:** WastedSpaceGB
**Sort By:** WastedSpaceGB (Descending)
**Top N:** 20

### 3. Duplicates by File Extension
**Visual Type:** Pie Chart or Treemap
**Group:** FileExtension
**Value:** WastedSpaceGB

### 4. Duplicate Files Detailed Table
**Visual Type:** Table
**Columns:**
- FileName
- FileExtension
- FileSizeMB
- DuplicateCount
- WastedSpaceMB
- StorageAccounts
- FileShares

**Sorting:** WastedSpaceMB Descending

### 5. Duplicate Files Locations Drill-Down
**Visual Type:** Matrix
**Rows:** 
1. StorageAccount
2. FileShare
3. FilePath

**Values:** 
- Count of FilePath
- Sum of FileSizeMB

**Filters:** IsDuplicate = "Yes"

### 6. Wasted Space Trend
**Visual Type:** Line Chart
**Axis:** ScanTimestamp (Date)
**Values:** WastedSpaceGB
**Note:** Requires multiple scan history

### 7. Duplicate Detection Coverage
**Visual Type:** Gauge
**Value:** 
```DAX
Files Scanned = COUNTROWS('FileInventory')
Files with Hash = COUNTROWS(FILTER('FileInventory', 'FileInventory'[FileHash] <> "SKIPPED_TOO_LARGE" && 'FileInventory'[FileHash] <> "ERROR"))
Coverage % = DIVIDE([Files with Hash], [Files Scanned], 0) * 100
```

## DAX Measures

### Total Wasted Space (GB)
```DAX
Total Wasted Space GB = 
SUMX(
    'DuplicateFilesReport',
    'DuplicateFilesReport'[WastedSpaceGB]
)
```

### Potential Savings Percentage
```DAX
Potential Savings % = 
VAR TotalStorage = SUM('FileInventory'[FileSizeGB])
VAR WastedSpace = [Total Wasted Space GB]
RETURN
DIVIDE(WastedSpace, TotalStorage, 0) * 100
```

### Average Duplicate Group Size
```DAX
Avg Duplicates per Group = 
AVERAGEX(
    'DuplicateFilesReport',
    'DuplicateFilesReport'[DuplicateCount]
)
```

### Files by Duplicate Status
```DAX
Unique Files = 
COUNTROWS(
    FILTER('FileInventory', 'FileInventory'[IsDuplicate] = "No")
)

Duplicate Files = 
COUNTROWS(
    FILTER('FileInventory', 'FileInventory'[IsDuplicate] = "Yes")
)
```

## Dashboard Layout Recommendation

```
┌─────────────────────────────────────────────────────────────┐
│  DUPLICATE FILES ANALYSIS                    [Scan Date]    │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ Total Dupes  │ Wasted Space │ Dup Groups   │ Potential Save │
│   [Card]     │   [Card]     │  [Card]      │    [Card]      │
├──────────────┴──────────────┴──────────────┴────────────────┤
│                                                               │
│  Top 20 Files by Wasted Space                                │
│  [Horizontal Bar Chart]                                      │
│                                                               │
├────────────────────────────┬─────────────────────────────────┤
│                            │                                 │
│  Duplicates by Extension   │  Duplicate Coverage             │
│  [Treemap]                 │  [Gauge]                        │
│                            │                                 │
├────────────────────────────┴─────────────────────────────────┤
│                                                               │
│  Duplicate Files Detail Table                                │
│  [Table with sorting and filtering]                          │
│                                                               │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  File Locations Drill-Down                                   │
│  [Matrix: StorageAccount > FileShare > FilePath]             │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

## Slicers and Filters

Add these slicers for interactive filtering:
1. **Storage Account** (Multi-select)
2. **File Share** (Multi-select)
3. **File Extension** (Multi-select)
4. **Duplicate Count Range** (Slider: 2-10+)
5. **File Size Range** (Slider: MB/GB)
6. **Scan Date** (Date range)

## Color Coding Recommendations

- **High Waste** (>1 GB per group): Red (#C00000)
- **Medium Waste** (100 MB - 1 GB): Orange (#FFA500)
- **Low Waste** (<100 MB): Yellow (#FFD700)
- **No Duplicates**: Green (#70AD47)

## Tooltips

Enhance visuals with custom tooltips showing:
- All file locations (from AllLocations column)
- Last modified date of files
- Storage accounts and shares involved
- Exact wasted space calculation

## Refresh Schedule

- Schedule automatic refresh in Power BI Service to pull latest CSV files
- Recommended: Daily refresh after automation account runs (Sundays 3 AM UTC)

## Actions and Insights

### Recommended Actions Based on Data:
1. **High Priority**: Files with WastedSpaceGB > 1
   - Review and consolidate
   - Consider deduplication

2. **Medium Priority**: Files with DuplicateCount > 5
   - Likely unnecessary copies
   - Investigate origin

3. **Low Priority**: Small files (<10 MB) with few duplicates
   - May be intentional backups
   - Lower storage impact

## Notes

- **Hash Calculation Limit**: Files larger than 100 MB are marked as "SKIPPED_TOO_LARGE" to avoid performance issues
- **Hash Method**: MD5 hash is used for content comparison
- **Update Frequency**: File inventory and duplicate reports are generated during scheduled automation runs
- **Historical Tracking**: Keep previous CSVs for trend analysis over time
