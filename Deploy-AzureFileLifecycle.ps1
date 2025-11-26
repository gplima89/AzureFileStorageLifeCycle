<#
.SYNOPSIS
    Deployment script for Azure File Storage Lifecycle Management
    
.DESCRIPTION
    Deploys the Automation Account, uploads the runbook, and configures role assignments
    
.PARAMETER ResourceGroupName
    Resource group for the Automation Account
    
.PARAMETER AutomationAccountName
    Name of the Automation Account to create
    
.PARAMETER Location
    Azure region for deployment
    
.PARAMETER ConfigStorageAccountName
    Storage account name for configuration files
    
.PARAMETER AuditStorageAccountName
    Storage account name for audit logs and file inventory
    
.PARAMETER StorageAccountsToManage
    Array of storage account resource IDs to grant permissions
    
.EXAMPLE
    .\Deploy-AzureFileLifecycle.ps1 -ResourceGroupName "rg-file-lifecycle" -AutomationAccountName "aa-file-lifecycle"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$AutomationAccountName,
    
    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",
    
    [Parameter(Mandatory = $true)]
    [string]$ConfigStorageAccountName,
    
    [Parameter(Mandatory = $true)]
    [string]$AuditStorageAccountName,
    
    [Parameter(Mandatory = $false)]
    [string[]]$StorageAccountsToManage = @()
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Azure File Storage Lifecycle Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Step 1: Create Resource Group
Write-Host "`n[1/7] Creating resource group..." -ForegroundColor Yellow
$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
    Write-Host "✓ Resource group created: $ResourceGroupName" -ForegroundColor Green
}
else {
    Write-Host "✓ Resource group already exists: $ResourceGroupName" -ForegroundColor Green
}

# Step 2: Deploy Automation Account
Write-Host "`n[2/7] Deploying Automation Account..." -ForegroundColor Yellow

# Calculate next Sunday at 2 AM UTC
$today = Get-Date
$daysUntilSunday = (7 - [int]$today.DayOfWeek) % 7
if ($daysUntilSunday -eq 0) { $daysUntilSunday = 7 }
$nextSunday = $today.AddDays($daysUntilSunday).Date.AddHours(2)
$startTimeUTC = $nextSunday.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss+00:00")

$params = @{
    automationAccountName           = $AutomationAccountName
    location                        = $Location
    scheduleStartTime               = $startTimeUTC
    configurationStorageAccountName = $ConfigStorageAccountName
}

$deployment = New-AzResourceGroupDeployment `
    -ResourceGroupName $ResourceGroupName `
    -TemplateFile "./templates/automation-account.json" `
    -TemplateParameterObject $params `
    -Name "deployment-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

Write-Host "✓ Automation Account deployed: $AutomationAccountName" -ForegroundColor Green
Write-Host "  Principal ID: $($deployment.Outputs.automationAccountPrincipalId.Value)" -ForegroundColor Gray

$principalId = $deployment.Outputs.automationAccountPrincipalId.Value

# Step 3: Wait for managed identity propagation
Write-Host "`n[3/7] Waiting for managed identity propagation..." -ForegroundColor Yellow
Start-Sleep -Seconds 30
Write-Host "✓ Identity propagated" -ForegroundColor Green

# Step 4: Upload Runbook
Write-Host "`n[4/7] Uploading runbook..." -ForegroundColor Yellow
$runbookPath = "./src/runbooks/AzureFileStorageLifecycle.ps1"

Import-AzAutomationRunbook `
    -ResourceGroupName $ResourceGroupName `
    -AutomationAccountName $AutomationAccountName `
    -Path $runbookPath `
    -Name "AzureFileStorageLifecycle" `
    -Type PowerShell `
    -Force | Out-Null

Publish-AzAutomationRunbook `
    -ResourceGroupName $ResourceGroupName `
    -AutomationAccountName $AutomationAccountName `
    -Name "AzureFileStorageLifecycle" | Out-Null

Write-Host "✓ Runbook uploaded and published" -ForegroundColor Green

# Link runbook to schedule
Write-Host "  Linking runbook to schedule..." -ForegroundColor Gray
$scheduleName = "WeeklySunday2AM"
$configBlobUrl = "https://$ConfigStorageAccountName.blob.core.windows.net/config/lifecycle-rules.json"

Register-AzAutomationScheduledRunbook `
    -ResourceGroupName $ResourceGroupName `
    -AutomationAccountName $AutomationAccountName `
    -RunbookName "AzureFileStorageLifecycle" `
    -ScheduleName $scheduleName `
    -Parameters @{ ConfigurationPath = $configBlobUrl } `
    -ErrorAction SilentlyContinue | Out-Null

Write-Host "✓ Runbook linked to schedule" -ForegroundColor Green

# Step 5: Assign permissions to audit storage account
Write-Host "`n[5/7] Assigning permissions to audit storage account..." -ForegroundColor Yellow
$auditStorageAccount = Get-AzStorageAccount | Where-Object { $_.StorageAccountName -eq $AuditStorageAccountName }
if ($auditStorageAccount) {
    $roleAssignment = New-AzRoleAssignment `
        -ObjectId $principalId `
        -RoleDefinitionName "Storage Blob Data Contributor" `
        -Scope $auditStorageAccount.Id `
        -ErrorAction SilentlyContinue
    Write-Host "✓ Permissions assigned to audit storage account" -ForegroundColor Green
}
else {
    Write-Host "⚠ Audit storage account not found: $AuditStorageAccountName" -ForegroundColor Yellow
}

# Step 6: Assign permissions to managed storage accounts
Write-Host "`n[6/7] Assigning permissions to managed storage accounts..." -ForegroundColor Yellow
foreach ($storageAccountId in $StorageAccountsToManage) {
    try {
        New-AzRoleAssignment `
            -ObjectId $principalId `
            -RoleDefinitionName "Storage File Data SMB Share Contributor" `
            -Scope $storageAccountId `
            -ErrorAction SilentlyContinue | Out-Null
        
        $storageAccountName = ($storageAccountId -split '/')[-1]
        Write-Host "  ✓ Permissions assigned to: $storageAccountName" -ForegroundColor Green
    }
    catch {
        Write-Host "  ⚠ Failed to assign permissions to: $storageAccountId" -ForegroundColor Yellow
    }
}

# Step 7: Upload configuration
Write-Host "`n[7/7] Uploading configuration..." -ForegroundColor Yellow
$configStorage = Get-AzStorageAccount | Where-Object { $_.StorageAccountName -eq $ConfigStorageAccountName }
if ($configStorage) {
    $ctx = $configStorage.Context
    
    # Create container if it doesn't exist
    $container = Get-AzStorageContainer -Context $ctx -Name "config" -ErrorAction SilentlyContinue
    if (-not $container) {
        New-AzStorageContainer -Context $ctx -Name "config" -Permission Off | Out-Null
    }
    
    # Upload configuration
    Set-AzStorageBlobContent `
        -Context $ctx `
        -Container "config" `
        -File "./config/lifecycle-rules.json" `
        -Blob "lifecycle-rules.json" `
        -Force | Out-Null
    
    Write-Host "✓ Configuration uploaded" -ForegroundColor Green
}
else {
    Write-Host "⚠ Configuration storage account not found: $ConfigStorageAccountName" -ForegroundColor Yellow
    Write-Host "  Please upload ./config/lifecycle-rules.json manually" -ForegroundColor Yellow
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "1. Edit ./config/lifecycle-rules.json with your storage accounts and rules" -ForegroundColor White
Write-Host "2. Update the configuration in blob storage if needed" -ForegroundColor White
Write-Host "3. Test with dry run:" -ForegroundColor White
Write-Host "   Start-AzAutomationRunbook -Name 'AzureFileStorageLifecycle' -Parameters @{DryRun=`$true} -ResourceGroupName '$ResourceGroupName' -AutomationAccountName '$AutomationAccountName'" -ForegroundColor Gray
Write-Host "`nScheduled to run: Every Sunday at 2:00 AM UTC (starting $startTimeUTC)" -ForegroundColor Cyan
Write-Host "Automation Account: $AutomationAccountName" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Cyan
