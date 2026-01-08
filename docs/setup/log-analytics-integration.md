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
5. Use the following schema (or deploy via ARM template):

```json
{
    "columns": [
        { "name": "TimeGenerated", "type": "datetime" },
        { "name": "StorageAccount", "type": "string" },
        { "name": "FileShare", "type": "string" },
        { "name": "Directory", "type": "string" },
        { "name": "FilePath", "type": "string" },
        { "name": "FileName", "type": "string" },
        { "name": "FileExtension", "type": "string" },
        { "name": "FileCategory", "type": "string" },
        { "name": "FileSizeBytes", "type": "long" },
        { "name": "FileSizeKB", "type": "real" },
        { "name": "FileSizeMB", "type": "real" },
        { "name": "FileSizeGB", "type": "real" },
        { "name": "FileSizeTB", "type": "real" },
        { "name": "LastModified", "type": "datetime" },
        { "name": "LastModifiedDate", "type": "string" },
        { "name": "Created", "type": "datetime" },
        { "name": "CreatedDate", "type": "string" },
        { "name": "AgeInDays", "type": "int" },
        { "name": "AgeBucket", "type": "string" },
        { "name": "SizeBucket", "type": "string" },
        { "name": "ContentType", "type": "string" },
        { "name": "FileHash", "type": "string" },
        { "name": "IsDuplicate", "type": "string" },
        { "name": "DuplicateCount", "type": "int" },
        { "name": "ScanTimestamp", "type": "string" },
        { "name": "ScanTimestampUTC", "type": "string" },
        { "name": "ExecutionId", "type": "string" },
        { "name": "ExecutionHost", "type": "string" }
    ]
}
```

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

Grant the Automation Account's Managed Identity permission to send data:

```powershell
# Get the Automation Account's Managed Identity Object ID
$automationAccountName = "your-automation-account"
$resourceGroup = "your-resource-group"

$automationAccount = Get-AzAutomationAccount -ResourceGroupName $resourceGroup -Name $automationAccountName
$identityId = (Get-AzADServicePrincipal -DisplayName $automationAccountName).Id

# Assign "Monitoring Metrics Publisher" role on the DCR
$dcrResourceId = "/subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionRules/{dcr-name}"

New-AzRoleAssignment `
    -ObjectId $identityId `
    -RoleDefinitionName "Monitoring Metrics Publisher" `
    -Scope $dcrResourceId
```

### Step 5: Configure the Runbook

#### Option A: Using runbook parameters

```powershell
.\AzureFileStorageLifecycle.ps1 `
    -ConfigurationPath ".\config\lifecycle-rules.json" `
    -SendToLogAnalytics `
    -LogAnalyticsDceEndpoint "https://stgfilelifecycledcedp-mgco.canadacentral-1.ingest.monitor.azure.com" `
    -LogAnalyticsDcrImmutableId "dcr-f8b28d4ed32f4064a56f7b5230a8b1e5" `
    -LogAnalyticsStreamName "Custom-StgFileLifeCycle01_CL" `
    -LogAnalyticsTableName "StgFileLifeCycle01_CL"
```

#### Option B: Using configuration file

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

1. **401 Unauthorized**
   - Verify the Managed Identity has "Monitoring Metrics Publisher" role on the DCR
   - Ensure the DCR Immutable ID is correct

2. **404 Not Found**
   - Check the DCE endpoint URL is correct
   - Verify the stream name matches the DCR configuration

3. **400 Bad Request**
   - Schema mismatch between sent data and DCR definition
   - Check for missing required fields (TimeGenerated is mandatory)

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

## Your Configuration

Based on your setup, use these values:

| Setting | Value |
|---------|-------|
| **DCE Endpoint** | `https://stgfilelifecycledcedp-mgco.canadacentral-1.ingest.monitor.azure.com` |
| **DCR Immutable ID** | `dcr-f8b28d4ed32f4064a56f7b5230a8b1e5` |
| **Stream Name** | `Custom-StgFileLifeCycle01_CL` |
| **Table Name** | `StgFileLifeCycle01_CL` |
