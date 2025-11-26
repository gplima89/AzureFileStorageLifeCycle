# Power BI Dashboard - File Size Analysis

This folder contains resources for creating a Power BI dashboard to visualize file storage data in a TreeSize-like format.

## Dashboard Overview

The Power BI dashboard provides:

1. **File Size Treemap** - Hierarchical view of storage consumption by folder
2. **Top Files by Size** - List of largest files across all storage accounts
3. **Size Distribution** - Charts showing file size distribution
4. **Age Analysis** - File age breakdown and trends
5. **Category Analysis** - Storage usage by file type/category

## Setting Up the Dashboard

### Prerequisites

- Power BI Desktop (free download from Microsoft)
- Access to the Azure Blob Storage containing file inventory CSVs
- Azure AD account with read access to the storage account

### Step 1: Connect to Data Source

1. Open Power BI Desktop
2. Click **Get Data** → **Azure** → **Azure Blob Storage**
3. Enter your storage account URL: `https://<storage-account>.blob.core.windows.net`
4. Navigate to the `file-inventory` container
5. Select `file-inventory_latest.csv`

### Step 2: Data Transformation

Apply these transformations in Power Query Editor:

```powerquery
let
    Source = AzureStorage.Blobs("https://yourstorageaccount.blob.core.windows.net"),
    fileInventory = Source{[Name="file-inventory"]}[Data],
    latestFile = fileInventory{[Name="file-inventory_latest.csv"]}[Content],
    csvContent = Csv.Document(latestFile, [Delimiter=",", Columns=17, Encoding=65001, QuoteStyle=QuoteStyle.None]),
    promotedHeaders = Table.PromoteHeaders(csvContent, [PromoteAllScalars=true]),
    typedColumns = Table.TransformColumnTypes(promotedHeaders, {
        {"StorageAccount", type text},
        {"FileShare", type text},
        {"Directory", type text},
        {"FilePath", type text},
        {"FileName", type text},
        {"FileExtension", type text},
        {"FileCategory", type text},
        {"FileSizeBytes", Int64.Type},
        {"FileSizeKB", type number},
        {"FileSizeMB", type number},
        {"FileSizeGB", type number},
        {"FileSizeTB", type number},
        {"LastModified", type datetime},
        {"LastModifiedDate", type date},
        {"Created", type datetime},
        {"CreatedDate", type date},
        {"AgeInDays", Int64.Type},
        {"AgeBucket", type text},
        {"SizeBucket", type text},
        {"ScanTimestamp", type datetime}
    })
in
    typedColumns
```

### Step 3: Create Measures

Add these DAX measures for analysis:

```dax
// Total Storage Size
Total Size (GB) = SUM('FileInventory'[FileSizeGB])

// Total File Count
Total Files = COUNTROWS('FileInventory')

// Average File Size
Avg File Size (MB) = AVERAGE('FileInventory'[FileSizeMB])

// Largest File
Largest File (GB) = MAX('FileInventory'[FileSizeGB])

// Files Over 1GB
Large Files Count = CALCULATE(
    COUNTROWS('FileInventory'),
    'FileInventory'[FileSizeGB] >= 1
)

// Storage by Category
Storage by Category = 
SUMMARIZE(
    'FileInventory',
    'FileInventory'[FileCategory],
    "Total GB", SUM('FileInventory'[FileSizeGB]),
    "File Count", COUNTROWS('FileInventory')
)

// Old Files (>365 days)
Old Files Count = CALCULATE(
    COUNTROWS('FileInventory'),
    'FileInventory'[AgeInDays] > 365
)

// Path Hierarchy for Treemap
Path Level 1 = 
VAR PathParts = PATHITEM(SUBSTITUTE('FileInventory'[FilePath], "/", "|"), 1)
RETURN IF(ISBLANK(PathParts), "Root", PathParts)

Path Level 2 = 
VAR PathParts = PATHITEM(SUBSTITUTE('FileInventory'[FilePath], "/", "|"), 2)
RETURN IF(ISBLANK(PathParts), "[Files]", PathParts)

Path Level 3 = 
VAR PathParts = PATHITEM(SUBSTITUTE('FileInventory'[FilePath], "/", "|"), 3)
RETURN IF(ISBLANK(PathParts), "[Files]", PathParts)
```

### Step 4: Create Visualizations

#### 4.1 Treemap (TreeSize-like view)

1. Add a **Treemap** visual
2. Group: `StorageAccount` → `FileShare` → `Path Level 1` → `Path Level 2`
3. Values: `Total Size (GB)`
4. Enable data labels to show size values

#### 4.2 Top 100 Largest Files Table

1. Add a **Table** visual
2. Columns: `FileName`, `FilePath`, `FileSizeGB`, `FileCategory`, `LastModified`, `StorageAccount`
3. Apply Top N filter: Top 100 by `FileSizeGB`

#### 4.3 Size Distribution Bar Chart

1. Add a **Clustered Bar Chart**
2. Axis: `SizeBucket`
3. Values: `Total Files`
4. Sort by custom order

#### 4.4 Age Distribution Pie Chart

1. Add a **Pie Chart**
2. Legend: `AgeBucket`
3. Values: `Total Size (GB)`

#### 4.5 Category Breakdown

1. Add a **Donut Chart**
2. Legend: `FileCategory`
3. Values: `Total Size (GB)`

#### 4.6 Storage Account Summary Cards

1. Add **Card** visuals for:
   - Total Size (GB)
   - Total Files
   - Largest File (GB)
   - Large Files Count

### Step 5: Add Slicers

Add slicers for interactive filtering:

- Storage Account
- File Share
- File Category
- Age Bucket
- Size Bucket
- Date Range (LastModified)

### Step 6: Configure Refresh

1. **Publish to Power BI Service**
2. Configure **Scheduled Refresh**:
   - Go to Dataset Settings
   - Data source credentials: Use OAuth2 or SAS token
   - Schedule: Weekly after lifecycle job runs (e.g., Sunday 4AM)

## Sample Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  Azure File Storage Analysis Dashboard                          │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────┤
│ Total Size  │ Total Files │ Avg Size    │ Large Files │ Old     │
│   2.5 TB    │   125,432   │   18.5 MB   │   1,234     │ 45,231  │
├─────────────┴─────────────┴─────────────┴─────────────┴─────────┤
│ ┌─────────────────────────────┐  ┌────────────────────────────┐ │
│ │   TREEMAP - Storage by Path │  │    Size by Category        │ │
│ │   ┌─────────────────────┐   │  │    ┌────────────────────┐  │ │
│ │   │ Documents    │ Imgs │   │  │    │   Documents: 40%   │  │ │
│ │   │   500 GB     │150GB │   │  │    │   Videos: 25%      │  │ │
│ │   ├───────────────┼─────┤   │  │    │   Archives: 20%    │  │ │
│ │   │ Archive      │Other │   │  │    │   Other: 15%       │  │ │
│ │   │   800 GB     │50GB  │   │  │    └────────────────────┘  │ │
│ │   └─────────────────────┘   │  └────────────────────────────┘ │
│ └─────────────────────────────┘                                 │
├─────────────────────────────────────────────────────────────────┤
│ Top 10 Largest Files                                            │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ File Name          │ Size (GB) │ Category │ Last Modified │   │
│ │ backup_2024.zip    │   25.5    │ Archive  │ 2024-01-15    │   │
│ │ database.bak       │   18.2    │ Database │ 2024-06-20    │   │
│ │ video_project.mp4  │   12.8    │ Video    │ 2024-03-10    │   │
│ └───────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Data Model

The file inventory CSV includes these columns optimized for Power BI analysis:

| Column | Type | Description |
|--------|------|-------------|
| StorageAccount | Text | Storage account name |
| FileShare | Text | File share name |
| Directory | Text | Parent directory path |
| FilePath | Text | Full file path |
| FileName | Text | File name only |
| FileExtension | Text | File extension |
| FileCategory | Text | Category (Documents, Images, etc.) |
| FileSizeBytes | Integer | Size in bytes |
| FileSizeKB | Decimal | Size in KB |
| FileSizeMB | Decimal | Size in MB |
| FileSizeGB | Decimal | Size in GB |
| FileSizeTB | Decimal | Size in TB |
| LastModified | DateTime | Last modification timestamp |
| LastModifiedDate | Date | Last modification date |
| Created | DateTime | Creation timestamp |
| CreatedDate | Date | Creation date |
| AgeInDays | Integer | Days since last modification |
| AgeBucket | Text | Age range category |
| SizeBucket | Text | Size range category |
| ScanTimestamp | DateTime | When the scan was performed |

## Troubleshooting

### Connection Issues
- Ensure the managed identity or service principal has "Storage Blob Data Reader" role
- Check firewall settings on the storage account

### Performance
- Use incremental refresh for large datasets
- Consider aggregating data for historical trends
- Filter to specific storage accounts if performance is slow

### Missing Data
- Verify the lifecycle runbook completed successfully
- Check that `file-inventory_latest.csv` exists in the blob container
