# Log Analytics Integration Setup

This guide explains how to configure Azure Log Analytics integration for the Azure File Storage Lifecycle Management solution using the modern **Logs Ingestion API** with **Data Collection Rules (DCR)** and **Managed Identity** authentication.

## Overview

The solution streams file inventory data to Azure Log Analytics, enabling:
- Real-time visibility into file storage usage
- Custom KQL queries for analysis
- Power BI dashboards and reports
- Alerts based on storage metrics

## Prerequisites

- Azure Log Analytics Workspace
- Azure Automation Account with System-Assigned Managed Identity
- Data Collection Endpoint (DCE)
- Data Collection Rule (DCR)

## Architecture

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│  Automation Account │────▶│  Data Collection    │────▶│  Log Analytics      │
│  (Managed Identity) │     │  Endpoint (DCE)     │     │  Workspace          │
└─────────────────────┘     └─────────────────────┘     └─────────────────────┘
                                     │
                                     │
                            ┌────────▼────────┐
                            │ Data Collection │
                            │  Rule (DCR)     │
                            └─────────────────┘
```

## Setup Steps

### Step 1: Create a Data Collection Endpoint (DCE)

1. In the Azure Portal, navigate to **Monitor** > **Data Collection Endpoints**
2. Click **+ Create**
3. Configure:
   - **Name**: `stgfilelifecycle-dce` (or your preferred name)
   - **Subscription**: Your subscription
   - **Resource Group**: Your resource group
   - **Region**: Same region as your Log Analytics Workspace (e.g., `Canada Central`)
4. Click **Review + create** > **Create**
5. After creation, note the **Logs Ingestion URI** (e.g., `https://stgfilelifecycledcedp-mgco.canadacentral-1.ingest.monitor.azure.com`)

### Step 2: Create the Custom Table in Log Analytics

Before creating the DCR, create the custom table schema in your Log Analytics workspace:

1. Navigate to your **Log Analytics Workspace**
2. Go to **Settings** > **Tables**
3. Click **+ Create** > **New custom log (DCR-based)**
4. Table name: `StgFileLifeCycle01_CL`

Use the following schema (16 columns required for file inventory):

```json
{
    "columns": [
        { "name": "TimeGenerated", "type": "datetime" },
        { "name": "StorageAccount", "type": "string" },
        { "name": "FileShare", "type": "string" },
        { "name": "FilePath", "type": "string" },
        { "name": "FileName", "type": "string" },
        { "name": "FileExtension", "type": "string" },
        { "name": "FileSizeBytes", "type": "long" },
        { "name": "FileSizeMB", "type": "real" },
        { "name": "FileSizeGB", "type": "real" },
        { "name": "LastModified", "type": "datetime" },
        { "name": "Created", "type": "datetime" },
        { "name": "AgeInDays", "type": "int" },
        { "name": "FileHash", "type": "string" },
        { "name": "IsDuplicate", "type": "string" },
        { "name": "DuplicateCount", "type": "int" },
        { "name": "ScanTimestamp", "type": "string" }
    ]
}
```

> **Important**: The DCR stream declaration must include **all** fields above, including `TimeGenerated`. The runbook sends flat JSON objects, not wrapped in a `properties` object.

### Step 3: Create a Data Collection Rule (DCR)

You can create the DCR using the Azure Portal or the provided ARM template.

#### Option A: Deploy using ARM Template

Use the provided `SampleDCRTemplate.json` in the repository root:

```powershell
# Deploy DCR using ARM template
$params = @{
    dcrName = "dcr-stgfilelifecycle"
    dceResourceId = "/subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionEndpoints/{dce-name}"
    workspaceResourceId = "/subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace-name}"
    tableName = "StgFileLifeCycle01_CL"
}

New-AzResourceGroupDeployment `
    -ResourceGroupName "your-resource-group" `
    -TemplateFile ".\SampleDCRTemplate.json" `
    -TemplateParameterObject $params
```

#### Option B: Create via Azure Portal

1. Navigate to **Monitor** > **Data Collection Rules**
2. Click **+ Create**
3. **Basics**:
   - Name: `dcr-stgfilelifecycle`
   - Region: Same as your workspace
   - Data Collection Endpoint: Select the DCE created in Step 1
4. **Resources**: Skip (not needed for custom logs)
5. **Collect and deliver**:
   - Add a custom log data source with the schema above
   - Destination: Your Log Analytics Workspace
6. **Review + create** > **Create**

After creation, note:
- **DCR Immutable ID**: Found in the DCR properties (e.g., `dcr-f8b28d4ed32f4064a56f7b5230a8b1e5`)
- **Stream Name**: `Custom-StgFileLifeCycle01_CL`

### Step 4: Assign Permissions to Managed Identity

Grant the Automation Account's Managed Identity permission to send data. **This is critical** - the Logs Ingestion API requires the `Monitoring Metrics Publisher` role **directly on the DCR**:

```powershell
# Get the Automation Account's Managed Identity Object ID
$automationAccountName = "aa-file-lifecycle"
$resourceGroup = "rg-file-lifecycle"

$automationAccount = Get-AzAutomationAccount -ResourceGroupName $resourceGroup -Name $automationAccountName
$principalId = $automationAccount.Identity.PrincipalId

# Assign "Monitoring Metrics Publisher" role DIRECTLY on the DCR (required for Logs Ingestion API)
$dcrResourceId = "/subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionRules/{dcr-name}"

New-AzRoleAssignment `
    -ObjectId $principalId `
    -RoleDefinitionName "Monitoring Metrics Publisher" `
    -Scope $dcrResourceId

# Also assign Log Analytics Contributor on the resource group for querying
New-AzRoleAssignment `
    -ObjectId $principalId `
    -RoleDefinitionName "Log Analytics Contributor" `
    -Scope "/subscriptions/{sub-id}/resourceGroups/{rg}"
```

> **Important**: Role assignments can take **up to 5 minutes to propagate**. If you see 401 errors immediately after assigning roles, wait a few minutes and try again.

### Required Roles Summary

| Role | Scope | Purpose |
|------|-------|---------|
| Monitoring Metrics Publisher | DCR resource | Send data via Logs Ingestion API |
| Log Analytics Contributor | Resource Group | Query workspace data |

### Step 5: Configure the Runbook

#### Option A: Using Automation Variables (Recommended for Schedules)

This is the **recommended approach** when using Azure Automation schedules, as schedules cannot pass parameters:

```powershell
$resourceGroupName = "rg-file-lifecycle"
$automationAccountName = "aa-file-lifecycle"

# Configure Log Analytics variables
New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName `
    -Name "LifeCycle_SendToLogAnalytics" -Value "true" -Encrypted $false

New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName `
    -Name "LifeCycle_LogAnalyticsDceEndpoint" `
    -Value "https://stgfilelifecycledcedp-mgco.canadacentral-1.ingest.monitor.azure.com" -Encrypted $false

New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName `
    -Name "LifeCycle_LogAnalyticsDcrImmutableId" -Value "dcr-f8b28d4ed32f4064a56f7b5230a8b1e5" -Encrypted $false

New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName `
    -Name "LifeCycle_LogAnalyticsStreamName" -Value "Custom-StgFileLifeCycle01_CL" -Encrypted $false

New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName `
    -Name "LifeCycle_LogAnalyticsTableName" -Value "StgFileLifeCycle01_CL" -Encrypted $false
```

The runbook will automatically read these variables when running.

#### Option B: Using runbook parameters

For manual or test runs, you can pass parameters directly:

```powershell
.\AzureFileStorageLifecycle.ps1 `
    -ConfigurationPath ".\config\lifecycle-rules.json" `
    -SendToLogAnalytics `
    -LogAnalyticsDceEndpoint "https://stgfilelifecycledcedp-mgco.canadacentral-1.ingest.monitor.azure.com" `
    -LogAnalyticsDcrImmutableId "dcr-f8b28d4ed32f4064a56f7b5230a8b1e5" `
    -LogAnalyticsStreamName "Custom-StgFileLifeCycle01_CL" `
    -LogAnalyticsTableName "StgFileLifeCycle01_CL"
```

#### Option C: Using configuration file

Update `config/lifecycle-rules.json`:

```json
{
    "globalSettings": {
        "logAnalytics": {
            "enabled": true,
            "dceEndpoint": "https://stgfilelifecycledcedp-mgco.canadacentral-1.ingest.monitor.azure.com",
            "dcrImmutableId": "dcr-f8b28d4ed32f4064a56f7b5230a8b1e5",
            "streamName": "Custom-StgFileLifeCycle01_CL",
            "tableName": "StgFileLifeCycle01_CL"
        }
    }
}
```

Then run with:
```powershell
.\AzureFileStorageLifecycle.ps1 -ConfigurationPath ".\config\lifecycle-rules.json" -SendToLogAnalytics
```

> **Priority Order**: Parameters > Automation Variables > Configuration File

## Sample KQL Queries

### Total Storage by Account
```kql
StgFileLifeCycle01_CL
| where TimeGenerated > ago(1d)
| summarize TotalSizeGB = sum(FileSizeGB) by StorageAccount
| order by TotalSizeGB desc
```

### Files by Category
```kql
StgFileLifeCycle01_CL
| where TimeGenerated > ago(1d)
| summarize FileCount = count(), TotalSizeGB = sum(FileSizeGB) by FileCategory
| order by TotalSizeGB desc
```

### Duplicate Files Analysis
```kql
StgFileLifeCycle01_CL
| where TimeGenerated > ago(1d)
| where IsDuplicate == "Yes"
| summarize DuplicateCount = count(), WastedSpaceGB = sum(FileSizeGB) by FileHash, FileName
| order by WastedSpaceGB desc
```

### Files by Age Bucket
```kql
StgFileLifeCycle01_CL
| where TimeGenerated > ago(1d)
| summarize FileCount = count(), TotalSizeGB = sum(FileSizeGB) by AgeBucket
| order by case(
    AgeBucket == "0-7 days", 1,
    AgeBucket == "8-30 days", 2,
    AgeBucket == "31-90 days", 3,
    AgeBucket == "91-180 days", 4,
    AgeBucket == "181-365 days", 5,
    AgeBucket == "1-2 years", 6,
    AgeBucket == "2-5 years", 7,
    8
)
```

### Storage Trend Over Time
```kql
StgFileLifeCycle01_CL
| summarize TotalSizeGB = sum(FileSizeGB) by bin(TimeGenerated, 1d), StorageAccount
| render timechart
```

## Troubleshooting

### Common Issues

1. **401 Unauthorized / InvalidToken**
   - Verify the Managed Identity has "Monitoring Metrics Publisher" role **directly on the DCR** (not just the resource group)
   - Wait 5+ minutes after role assignment for propagation
   - Ensure the DCR Immutable ID is correct
   - Check that the token audience is `https://monitor.azure.com`
   
   ```powershell
   # Verify role assignment
   Get-AzRoleAssignment -ObjectId $principalId -Scope $dcrResourceId
   ```

2. **404 Not Found**
   - Check the DCE endpoint URL is correct (should end with `.ingest.monitor.azure.com`)
   - Verify the stream name matches the DCR configuration exactly
   - Ensure DCE and DCR are in the same region as Log Analytics workspace

3. **400 Bad Request / Schema Mismatch**
   - Schema mismatch between sent data and DCR stream declaration
   - **TimeGenerated** must be included in the DCR stream declaration
   - Verify all field types match (datetime, string, long, real, int)
   - Check the DCR stream declaration includes all fields being sent

4. **Empty fields in Log Analytics**
   - Data is wrapped incorrectly (should be flat JSON, not nested in `properties`)
   - Verify the DCR stream declaration matches the flat schema
   
   Correct format:
   ```json
   [{"TimeGenerated":"2026-01-08T...","StorageAccount":"mystg","FileName":"test.txt"}]
   ```
   
   Incorrect format:
   ```json
   [{"TimeGenerated":"2026-01-08T...","properties":{"StorageAccount":"mystg"}}]
   ```

### Testing the Connection

Run the test function from the FileInventory module:

```powershell
Import-Module .\src\modules\FileInventory.psm1

Initialize-LogAnalyticsIngestion `
    -DceEndpoint "https://your-dce.region.ingest.monitor.azure.com" `
    -DcrImmutableId "dcr-your-immutable-id" `
    -StreamName "Custom-StgFileLifeCycle01_CL" `
    -TableName "StgFileLifeCycle01_CL"

Test-LogAnalyticsConnection
```

### Viewing Logs

Data typically appears in Log Analytics within 2-5 minutes. Query using:

```kql
StgFileLifeCycle01_CL
| where TimeGenerated > ago(1h)
| take 100
```

## Module Functions Reference

All Log Analytics functions are now integrated into the `FileInventory.psm1` module:

| Function | Description |
|----------|-------------|
| `Initialize-LogAnalyticsIngestion` | Configures DCE, DCR, and stream settings |
| `Send-ToLogAnalytics` | Sends generic data to Log Analytics |
| `Send-FileInventoryToLogAnalytics` | Sends file inventory with metadata |
| `Test-LogAnalyticsConnection` | Tests connectivity with a sample record |
| `Get-LogAnalyticsAccessToken` | Gets OAuth token via Managed Identity |
| `ConvertTo-LogAnalyticsJson` | Converts data to Log Analytics JSON format |

## Automation Account Setup

With the integrated module, you only need to upload **one module** to your Automation Account:

1. Navigate to your **Automation Account** > **Modules**
2. Click **+ Add a module**
3. Upload `FileInventory.psm1` from `src/modules/`
4. Runtime version: PowerShell 7.2

This single module includes both file inventory and Log Analytics functionality.

## Configuration Reference

After completing setup, note these values for your environment:

| Setting | Description | How to Find |
|---------|-------------|-------------|
| **DCE Endpoint** | Logs Ingestion URI | DCE Properties > Logs Ingestion > endpoint |
| **DCR Immutable ID** | Unique DCR identifier | DCR Properties > Immutable ID (starts with `dcr-`) |
| **Stream Name** | Custom stream name | Always `Custom-{TableName}` (e.g., `Custom-StgFileLifeCycle01_CL`) |
| **Table Name** | Log Analytics table | The table you created (e.g., `StgFileLifeCycle01_CL`) |

### Example Configuration

```powershell
# Example Automation Variables setup
$rg = "rg-file-lifecycle"
$aa = "aa-file-lifecycle"

# Your actual values - replace these!
$dceEndpoint = "https://your-dce-name.region.ingest.monitor.azure.com"
$dcrImmutableId = "dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
$streamName = "Custom-StgFileLifeCycle01_CL"
$tableName = "StgFileLifeCycle01_CL"

# Create variables
@{
    "LifeCycle_SendToLogAnalytics" = "true"
    "LifeCycle_LogAnalyticsDceEndpoint" = $dceEndpoint
    "LifeCycle_LogAnalyticsDcrImmutableId" = $dcrImmutableId
    "LifeCycle_LogAnalyticsStreamName" = $streamName
    "LifeCycle_LogAnalyticsTableName" = $tableName
}.GetEnumerator() | ForEach-Object {
    New-AzAutomationVariable -ResourceGroupName $rg -AutomationAccountName $aa `
        -Name $_.Key -Value $_.Value -Encrypted $false
}
```

## Verifying Data Ingestion

After running the lifecycle runbook, verify data appears in Log Analytics:

```kql
// Check recent ingestion
StgFileLifeCycle01_CL
| where TimeGenerated > ago(1h)
| take 10
| project TimeGenerated, StorageAccount, FileName, FileSizeBytes
```

Data typically appears within 2-5 minutes after the runbook completes.
