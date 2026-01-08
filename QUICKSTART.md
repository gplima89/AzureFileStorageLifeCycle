# Deployment Quick Start Guide

## Prerequisites Checklist

- [ ] Azure PowerShell module installed (`Install-Module -Name Az`)
- [ ] Logged into Azure (`Connect-AzAccount`)
- [ ] Resource group created
- [ ] Storage accounts created (config and audit)
- [ ] Log Analytics Workspace created (if using Log Analytics integration)
- [ ] Data Collection Endpoint (DCE) created (if using Log Analytics)
- [ ] Data Collection Rule (DCR) created (if using Log Analytics)

## Option 1: Using the Deployment Script (Recommended)

```powershell
# 1. Navigate to the project directory
cd "AzureFileStorageLifeCycle"

# 2. Run the deployment script
.\Deploy-AzureFileLifecycle.ps1 `
    -ResourceGroupName "rg-file-lifecycle" `
    -AutomationAccountName "aa-file-lifecycle" `
    -Location "eastus" `
    -ConfigStorageAccountName "stconfiglifecycle" `
    -AuditStorageAccountName "stauditlifecycle" `
    -StorageAccountsToManage @(
        "/subscriptions/YOUR-SUB-ID/resourceGroups/YOUR-RG/providers/Microsoft.Storage/storageAccounts/storage1",
        "/subscriptions/YOUR-SUB-ID/resourceGroups/YOUR-RG/providers/Microsoft.Storage/storageAccounts/storage2"
    )
```

## Option 2: Manual Deployment

### Step 1: Deploy Automation Account

```powershell
# Calculate next Sunday at 2 AM UTC
$today = Get-Date
$daysUntilSunday = (7 - [int]$today.DayOfWeek) % 7
if ($daysUntilSunday -eq 0) { $daysUntilSunday = 7 }
$nextSunday = $today.AddDays($daysUntilSunday).Date.AddHours(2)
$startTimeUTC = $nextSunday.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss+00:00")

# Deploy
$params = @{
    automationAccountName = "aa-file-lifecycle"
    location = "eastus"
    scheduleStartTime = $startTimeUTC
    configurationStorageAccountName = "stconfiglifecycle"
}

$deployment = New-AzResourceGroupDeployment `
    -ResourceGroupName "rg-file-lifecycle" `
    -TemplateFile "./templates/automation-account.json" `
    -TemplateParameterObject $params
```

### Step 2: Upload Runbook

```powershell
# Import and publish
Import-AzAutomationRunbook `
    -ResourceGroupName "rg-file-lifecycle" `
    -AutomationAccountName "aa-file-lifecycle" `
    -Path "./src/runbooks/AzureFileStorageLifecycle.ps1" `
    -Name "AzureFileStorageLifecycle" `
    -Type PowerShell `
    -Force

Publish-AzAutomationRunbook `
    -ResourceGroupName "rg-file-lifecycle" `
    -AutomationAccountName "aa-file-lifecycle" `
    -Name "AzureFileStorageLifecycle"
```

### Step 3: Assign Permissions

```powershell
# Get the Automation Account's managed identity principal ID
$principalId = $deployment.Outputs.automationAccountPrincipalId.Value

# Wait for identity propagation
Start-Sleep -Seconds 30

# Assign Storage Blob Data Contributor to audit storage account
New-AzRoleAssignment `
    -ObjectId $principalId `
    -RoleDefinitionName "Storage Blob Data Contributor" `
    -Scope "/subscriptions/YOUR-SUB-ID/resourceGroups/YOUR-RG/providers/Microsoft.Storage/storageAccounts/stauditlifecycle"

# Assign Storage File Data SMB Share Contributor to managed storage accounts
New-AzRoleAssignment `
    -ObjectId $principalId `
    -RoleDefinitionName "Storage File Data SMB Share Contributor" `
    -Scope "/subscriptions/YOUR-SUB-ID/resourceGroups/YOUR-RG/providers/Microsoft.Storage/storageAccounts/storage1"
```

### Step 4: Upload Configuration

```powershell
# Edit the configuration file first
code ./config/lifecycle-rules.json

# Then upload to blob storage
$storageAccount = Get-AzStorageAccount -ResourceGroupName "YOUR-RG" -Name "stconfiglifecycle"
$ctx = $storageAccount.Context

# Create container
New-AzStorageContainer -Context $ctx -Name "config" -Permission Off -ErrorAction SilentlyContinue

# Upload config
Set-AzStorageBlobContent `
    -Context $ctx `
    -Container "config" `
    -File "./config/lifecycle-rules.json" `
    -Blob "lifecycle-rules.json" `
    -Force
```

### Step 5: Test with Dry Run

```powershell
# Start runbook with DryRun parameter
$job = Start-AzAutomationRunbook `
    -ResourceGroupName "rg-file-lifecycle" `
    -AutomationAccountName "aa-file-lifecycle" `
    -Name "AzureFileStorageLifecycle" `
    -Parameters @{ DryRun = $true }

# Monitor the job
Get-AzAutomationJobOutput `
    -ResourceGroupName "rg-file-lifecycle" `
    -AutomationAccountName "aa-file-lifecycle" `
    -Id $job.JobId `
    -Stream "Output"
```

## Common Issues & Fixes

### Issue 1: "Configuration file not found"
**Solution:** Make sure you've uploaded the config to blob storage and the URL is accessible by the managed identity.

### Issue 2: "Failed to connect with Managed Identity"
**Solution:** Wait 60 seconds after creating the Automation Account, then try again.

### Issue 3: "Access denied" errors
**Solution:** Verify the managed identity has the correct role assignments:
```powershell
# Check role assignments
Get-AzRoleAssignment -ObjectId $principalId
```

### Issue 4: Schedule not triggering
**Solution:** Check the schedule start time is in the future:
```powershell
Get-AzAutomationSchedule `
    -ResourceGroupName "rg-file-lifecycle" `
    -AutomationAccountName "aa-file-lifecycle"
```

## Configuration File Template

Minimum required configuration:

```json
{
    "version": "1.0.0",
    "globalSettings": {
        "dryRun": true,
        "auditLogStorageAccount": "stauditlifecycle",
        "auditLogContainer": "audit-logs",
        "fileInventoryContainer": "file-inventory",
        "excludePatterns": ["*.tmp", "~$*"],
        "logAnalytics": {
            "enabled": true,
            "dceEndpoint": "https://your-dce.region.ingest.monitor.azure.com",
            "dcrImmutableId": "dcr-your-immutable-id",
            "streamName": "Custom-StgFileLifeCycle01_CL",
            "tableName": "StgFileLifeCycle01_CL"
        }
    },
    "storageAccounts": [
        {
            "name": "yourstorageaccount",
            "resourceGroup": "your-resource-group",
            "subscriptionId": "00000000-0000-0000-0000-000000000000",
            "enabled": true,
            "fileShares": [
                {
                    "name": "yourfileshare",
                    "enabled": true,
                    "rules": [
                        {
                            "name": "DeleteOldFiles",
                            "enabled": true,
                            "action": "delete",
                            "conditions": {
                                "lastModifiedDaysAgo": 90
                            }
                        }
                    ]
                }
            ]
        }
    ]
}
```

## Automation Variables (Recommended for Schedules)

Instead of passing parameters, configure Automation Variables:

```powershell
$rg = "rg-file-lifecycle"
$aa = "aa-file-lifecycle"

# Core variables
New-AzAutomationVariable -ResourceGroupName $rg -AutomationAccountName $aa `
    -Name "LifeCycle_ConfigurationPath" `
    -Value "https://stconfiglifecycle.blob.core.windows.net/config/lifecycle-rules.json" `
    -Encrypted $false

New-AzAutomationVariable -ResourceGroupName $rg -AutomationAccountName $aa `
    -Name "LifeCycle_DryRun" -Value "true" -Encrypted $false

# Log Analytics variables (if using Log Analytics)
New-AzAutomationVariable -ResourceGroupName $rg -AutomationAccountName $aa `
    -Name "LifeCycle_SendToLogAnalytics" -Value "true" -Encrypted $false

New-AzAutomationVariable -ResourceGroupName $rg -AutomationAccountName $aa `
    -Name "LifeCycle_LogAnalyticsDceEndpoint" `
    -Value "https://your-dce.region.ingest.monitor.azure.com" -Encrypted $false

New-AzAutomationVariable -ResourceGroupName $rg -AutomationAccountName $aa `
    -Name "LifeCycle_LogAnalyticsDcrImmutableId" -Value "dcr-xxx" -Encrypted $false

New-AzAutomationVariable -ResourceGroupName $rg -AutomationAccountName $aa `
    -Name "LifeCycle_LogAnalyticsStreamName" -Value "Custom-StgFileLifeCycle01_CL" -Encrypted $false

New-AzAutomationVariable -ResourceGroupName $rg -AutomationAccountName $aa `
    -Name "LifeCycle_LogAnalyticsTableName" -Value "StgFileLifeCycle01_CL" -Encrypted $false
```

## Testing Checklist

- [ ] Deploy Automation Account successfully
- [ ] Upload and publish runbook
- [ ] Assign storage permissions (wait 60 seconds after deployment)
- [ ] Configure Automation Variables (LifeCycle_* variables)
- [ ] Upload configuration to blob storage
- [ ] Assign Monitoring Metrics Publisher role on DCR (if using Log Analytics)
- [ ] Run dry run test
- [ ] Verify dry run logs in audit storage account
- [ ] Verify data in Log Analytics (if enabled)
- [ ] Disable dry run and run production test on non-critical data
- [ ] Verify schedule is active

## Monitoring

### View Automation Job Runs
```powershell
# View recent job runs
Get-AzAutomationJob `
    -ResourceGroupName "rg-file-lifecycle" `
    -AutomationAccountName "aa-file-lifecycle" | 
    Select-Object JobId, Status, StartTime, EndTime

# View audit logs
$auditStorage = Get-AzStorageAccount -ResourceGroupName "YOUR-RG" -Name "stauditlifecycle"
Get-AzStorageBlob -Context $auditStorage.Context -Container "audit-logs" |
    Sort-Object LastModified -Descending |
    Select-Object -First 10
```

### Query Log Analytics (if enabled)
```powershell
# Query file inventory from Log Analytics
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName "rg-file-lifecycle" -Name "your-workspace"
$query = @"
StgFileLifeCycle01_CL
| where TimeGenerated > ago(1d)
| summarize TotalFiles = count(), TotalSizeGB = sum(FileSizeGB) by StorageAccount, FileShare
| order by TotalSizeGB desc
"@

$result = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspace.CustomerId -Query $query
$result.Results
```
