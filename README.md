# Azure File Storage Lifecycle Management

A PowerShell solution to implement lifecycle management rules for Azure SMB File Storage, replicating Azure Storage Tasks functionality for Azure Files.

## Features

- **Lifecycle Rules**: Delete files and move to Cool/Archive tiers based on age, size, path, and file type
- **Multi-Account Support**: Manage multiple storage accounts and file shares with a single configuration
- **Managed Identity**: Uses Azure Automation Account system-assigned managed identity for secure authentication
- **Scheduled Execution**: Weekly runs on Sundays at 2:00 AM (configurable)
- **Audit Logging**: CSV-based audit logs for all delete and move operations
- **File Inventory**: Generate CSV reports of all files sorted by size, stored in Blob storage
- **Power BI Dashboard**: Visualize storage consumption with TreeSize-like treemap views

## Quick Start

### Prerequisites

- Azure subscription with Owner or Contributor access
- PowerShell 7+ or Azure Cloud Shell
- Az PowerShell module

### 1. Clone the Repository

```bash
git clone [https://github.com/your-org/AzureFileStorageLifeCycle.git](https://github.com/gplima89/AzureFileStorageLifeCycle.git)
cd AzureFileStorageLifeCycle
```

### 2. Deploy Automation Account

```powershell
# Deploy using ARM template
$params = @{
    automationAccountName = "aa-file-lifecycle"
    configurationStorageAccountName = "stconfiglifecycle"
}

New-AzResourceGroupDeployment `
    -ResourceGroupName "rg-file-lifecycle" `
    -TemplateFile "./templates/automation-account.json" `
    -TemplateParameterObject $params
```

### 3. Configure Lifecycle Rules

Edit `config/lifecycle-rules.json` to define your storage accounts and rules:

```json
{
    "storageAccounts": [
        {
            "name": "mystorageaccount",
            "resourceGroup": "my-resource-group",
            "subscriptionId": "00000000-0000-0000-0000-000000000000",
            "enabled": true,
            "fileShares": [
                {
                    "name": "myfileshare",
                    "rules": [
                        {
                            "name": "DeleteOldTempFiles",
                            "action": "delete",
                            "conditions": {
                                "lastModifiedDaysAgo": 30,
                                "fileExtensions": [".tmp", ".bak"]
                            }
                        }
                    ]
                }
            ]
        }
    ]
}
```

### 4. Upload Configuration and Run

```powershell
# Upload configuration
Set-AzStorageBlobContent -File "./config/lifecycle-rules.json" -Container "config" -Blob "lifecycle-rules.json"

# Test with dry run
Start-AzAutomationRunbook -Name "AzureFileStorageLifecycle" -Parameters @{ DryRun = $true }
```

## Repository Structure

```
AzureFileStorageLifeCycle/
├── config/
│   ├── lifecycle-rules.json          # Main configuration file
│   └── lifecycle-rules-schema.json   # JSON schema for validation
├── src/
│   ├── runbooks/
│   │   └── AzureFileStorageLifecycle.ps1  # Main runbook
│   └── modules/
│       ├── AuditLogging.psm1         # Audit logging functions
│       └── FileInventory.psm1        # File inventory functions
├── templates/
│   ├── automation-account.json       # ARM template for Automation Account
│   └── role-assignments.json         # ARM template for RBAC
├── docs/
│   ├── setup/
│   │   ├── automation-account-setup.md
│   │   ├── configure-lifecycle-rules.md
│   │   └── monitoring.md
│   └── powerbi/
│       ├── README.md                 # Power BI dashboard guide
│       └── data-model.json           # Data model definition
└── README.md
```

## Available Actions

| Action | Description |
|--------|-------------|
| `delete` | Permanently delete files matching conditions |
| `moveToCool` | Move files to Cool access tier |
| `moveToArchive` | Move files to Archive access tier |

## Rule Conditions

| Condition | Description | Example |
|-----------|-------------|---------|
| `lastModifiedDaysAgo` | Days since last modification | `90` |
| `createdDaysAgo` | Days since creation | `365` |
| `pathPrefix` | Path must start with | `"temp/"` |
| `pathSuffix` | Path must end with | `".backup"` |
| `fileExtensions` | File must have extension | `[".tmp", ".log"]` |
| `minSizeBytes` | Minimum file size | `1048576` (1MB) |
| `maxSizeBytes` | Maximum file size | `1073741824` (1GB) |

## Audit Logs

All operations are logged to CSV files in Blob storage:

```
audit-logs/
├── audit-log_2024-01-15_02-00-00.csv
├── audit-log_2024-01-22_02-00-00.csv
└── ...
```

Each log entry includes:
- Timestamp and storage account details
- File path, size, and age
- Action performed and rule name
- Status (Success/Failed) and error message
- Dry run indicator

## File Inventory

A complete file inventory sorted by size is generated:

```
file-inventory/
├── file-inventory_latest.csv        # Always latest scan
├── file-inventory_2024-01-15.csv    # Historical snapshots
└── ...
```

## Power BI Dashboard

![Dashboard Preview](docs/powerbi/dashboard-preview.png)

The included Power BI template provides:
- **Treemap View**: TreeSize-like visualization of storage by folder
- **Top Files**: List of largest files across all storage
- **Category Analysis**: Storage breakdown by file type
- **Age Analysis**: File distribution by age
- **Trend Analysis**: Storage growth over time

See [Power BI Dashboard Guide](docs/powerbi/README.md) for setup instructions.

## Schedule Configuration

Default schedule: **Weekly on Sundays at 2:00 AM UTC**

To modify the schedule:

```powershell
# Create custom schedule
New-AzAutomationSchedule `
    -ResourceGroupName "rg-file-lifecycle" `
    -AutomationAccountName "aa-file-lifecycle" `
    -Name "DailyMidnight" `
    -StartTime (Get-Date).AddDays(1).Date `
    -DayInterval 1 `
    -TimeZone "UTC"
```

## Required Permissions

The Automation Account managed identity needs these roles:

| Role | Scope | Purpose |
|------|-------|---------|
| Storage Blob Data Contributor | Audit storage account | Write audit logs and inventory |
| Storage File Data SMB Share Contributor | Managed storage accounts | Read/write/delete files |

## Documentation

- [Automation Account Setup](docs/setup/automation-account-setup.md)
- [Configure Lifecycle Rules](docs/setup/configure-lifecycle-rules.md)
- [Monitoring and Audit Logs](docs/setup/monitoring.md)
- [Power BI Dashboard](docs/powerbi/README.md)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues and feature requests, please use the GitHub Issues page
