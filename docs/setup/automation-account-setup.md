# Azure Automation Account Setup Guide

This guide walks through setting up the Azure Automation Account for running the File Storage Lifecycle Management runbook.

## Prerequisites

- Azure subscription with Owner or Contributor access
- PowerShell 7+ or Azure Cloud Shell
- Az PowerShell module installed

## Step 1: Create Resource Group

```powershell
# Variables
$resourceGroupName = "rg-file-lifecycle-mgmt"
$location = "eastus"

# Create resource group
New-AzResourceGroup -Name $resourceGroupName -Location $location
```

## Step 2: Deploy Automation Account

### Option A: Using ARM Template

```powershell
# Deploy the ARM template
$templateParams = @{
    automationAccountName = "aa-file-lifecycle"
    configurationStorageAccountName = "stconfiglifecycle"
    configurationContainerName = "config"
}

New-AzResourceGroupDeployment `
    -ResourceGroupName $resourceGroupName `
    -TemplateFile "./templates/automation-account.json" `
    -TemplateParameterObject $templateParams
```

### Option B: Manual Creation

```powershell
# Create Automation Account
$automationAccountName = "aa-file-lifecycle"

$automationAccount = New-AzAutomationAccount `
    -ResourceGroupName $resourceGroupName `
    -Name $automationAccountName `
    -Location $location `
    -Plan "Basic" `
    -AssignSystemIdentity

Write-Host "Automation Account Created: $($automationAccount.AutomationAccountName)"
Write-Host "Principal ID: $($automationAccount.Identity.PrincipalId)"
```

## Step 3: Install Required Modules

```powershell
# Import Az.Accounts module
New-AzAutomationModule `
    -ResourceGroupName $resourceGroupName `
    -AutomationAccountName $automationAccountName `
    -Name "Az.Accounts" `
    -ContentLinkUri "https://www.powershellgallery.com/api/v2/package/Az.Accounts"

# Wait for Az.Accounts to complete (required before Az.Storage)
Start-Sleep -Seconds 120

# Import Az.Storage module
New-AzAutomationModule `
    -ResourceGroupName $resourceGroupName `
    -AutomationAccountName $automationAccountName `
    -Name "Az.Storage" `
    -ContentLinkUri "https://www.powershellgallery.com/api/v2/package/Az.Storage"
```

## Step 4: Import the Runbook

```powershell
# Import the runbook
Import-AzAutomationRunbook `
    -ResourceGroupName $resourceGroupName `
    -AutomationAccountName $automationAccountName `
    -Name "AzureFileStorageLifecycle" `
    -Type PowerShell `
    -Path "./src/runbooks/AzureFileStorageLifecycle.ps1" `
    -Description "Azure File Storage Lifecycle Management"

# Publish the runbook
Publish-AzAutomationRunbook `
    -ResourceGroupName $resourceGroupName `
    -AutomationAccountName $automationAccountName `
    -Name "AzureFileStorageLifecycle"
```

## Step 5: Configure Managed Identity Permissions

The Automation Account's managed identity needs permissions on the storage accounts:

```powershell
# Get the Automation Account's managed identity
$automationAccount = Get-AzAutomationAccount `
    -ResourceGroupName $resourceGroupName `
    -Name $automationAccountName

$principalId = $automationAccount.Identity.PrincipalId

# For each storage account that needs to be managed:
$storageAccounts = @(
    @{ Name = "storageaccount1"; ResourceGroup = "rg-storage-prod" },
    @{ Name = "storageaccount2"; ResourceGroup = "rg-storage-dev" }
)

foreach ($sa in $storageAccounts) {
    $storageAccount = Get-AzStorageAccount `
        -ResourceGroupName $sa.ResourceGroup `
        -Name $sa.Name
    
    # Storage Blob Data Contributor (for audit logs)
    New-AzRoleAssignment `
        -ObjectId $principalId `
        -RoleDefinitionName "Storage Blob Data Contributor" `
        -Scope $storageAccount.Id
    
    # Storage File Data SMB Share Contributor (for file operations)
    New-AzRoleAssignment `
        -ObjectId $principalId `
        -RoleDefinitionName "Storage File Data SMB Share Contributor" `
        -Scope $storageAccount.Id
    
    Write-Host "Role assignments created for: $($sa.Name)"
}
```

## Step 6: Create the Schedule

```powershell
# Create weekly schedule (Sundays at 2:00 AM)
$scheduleName = "WeeklySunday2AM"

# Calculate next Sunday at 2:00 AM
$now = Get-Date
$daysUntilSunday = [int][DayOfWeek]::Sunday - [int]$now.DayOfWeek
if ($daysUntilSunday -le 0) { $daysUntilSunday += 7 }
$nextSunday = $now.AddDays($daysUntilSunday).Date.AddHours(2)

# Create the schedule
New-AzAutomationSchedule `
    -ResourceGroupName $resourceGroupName `
    -AutomationAccountName $automationAccountName `
    -Name $scheduleName `
    -StartTime $nextSunday `
    -WeekInterval 1 `
    -DaysOfWeek "Sunday" `
    -TimeZone "UTC" `
    -Description "Weekly schedule running every Sunday at 2:00 AM UTC"

Write-Host "Schedule created: $scheduleName"
Write-Host "Next run: $nextSunday"
```

## Step 7: Link Schedule to Runbook

```powershell
# Parameters for the runbook
$runbookParams = @{
    ConfigurationPath = "https://stconfiglifecycle.blob.core.windows.net/config/lifecycle-rules.json"
}

# Link schedule to runbook
Register-AzAutomationScheduledRunbook `
    -ResourceGroupName $resourceGroupName `
    -AutomationAccountName $automationAccountName `
    -RunbookName "AzureFileStorageLifecycle" `
    -ScheduleName $scheduleName `
    -Parameters $runbookParams
```

## Step 8: Upload Configuration File

```powershell
# Create storage account for configuration (if not exists)
$configStorageAccount = "stconfiglifecycle"
$configContainer = "config"

# Get or create storage account
$storage = Get-AzStorageAccount `
    -ResourceGroupName $resourceGroupName `
    -Name $configStorageAccount -ErrorAction SilentlyContinue

if (-not $storage) {
    $storage = New-AzStorageAccount `
        -ResourceGroupName $resourceGroupName `
        -Name $configStorageAccount `
        -Location $location `
        -SkuName "Standard_LRS" `
        -Kind "StorageV2"
}

# Create container
$ctx = $storage.Context
New-AzStorageContainer -Name $configContainer -Context $ctx -ErrorAction SilentlyContinue

# Upload configuration file
Set-AzStorageBlobContent `
    -File "./config/lifecycle-rules.json" `
    -Container $configContainer `
    -Blob "lifecycle-rules.json" `
    -Context $ctx `
    -Force

Write-Host "Configuration uploaded successfully"
```

## Step 9: Test the Runbook

### Dry Run Test

```powershell
# Start a test job in dry run mode
$params = @{
    ConfigurationPath = "https://stconfiglifecycle.blob.core.windows.net/config/lifecycle-rules.json"
    DryRun = $true
}

$job = Start-AzAutomationRunbook `
    -ResourceGroupName $resourceGroupName `
    -AutomationAccountName $automationAccountName `
    -Name "AzureFileStorageLifecycle" `
    -Parameters $params

Write-Host "Job started: $($job.JobId)"

# Wait for job completion
do {
    Start-Sleep -Seconds 10
    $job = Get-AzAutomationJob `
        -ResourceGroupName $resourceGroupName `
        -AutomationAccountName $automationAccountName `
        -Id $job.JobId
    Write-Host "Job status: $($job.Status)"
} while ($job.Status -notin @("Completed", "Failed", "Suspended"))

# Get job output
$output = Get-AzAutomationJobOutput `
    -ResourceGroupName $resourceGroupName `
    -AutomationAccountName $automationAccountName `
    -Id $job.JobId `
    -Stream "Output"

$output | ForEach-Object { Write-Host $_.Summary }
```

## Verification Checklist

- [ ] Automation Account created with system-assigned managed identity
- [ ] Az.Accounts and Az.Storage modules imported
- [ ] Runbook imported and published
- [ ] Managed identity has required roles on storage accounts
- [ ] Schedule created (Weekly, Sundays, 2:00 AM)
- [ ] Schedule linked to runbook with correct parameters
- [ ] Configuration file uploaded to blob storage
- [ ] Dry run test completed successfully

## Troubleshooting

### Module Import Issues

If modules fail to import:
1. Check the module import status in the Azure portal
2. Wait for Az.Accounts to complete before importing Az.Storage
3. Try importing modules from PowerShell Gallery directly

### Authentication Issues

If the runbook fails to authenticate:
1. Verify the managed identity is enabled
2. Check role assignments on storage accounts
3. Verify the subscription IDs in configuration

### Schedule Not Running

If the schedule doesn't trigger:
1. Verify the schedule is enabled
2. Check the time zone settings
3. Verify the job schedule link exists

## Next Steps

1. [Configure Lifecycle Rules](./configure-lifecycle-rules.md)
2. [Set up Power BI Dashboard](../powerbi/README.md)
3. [Monitor and Review Audit Logs](./monitoring.md)
