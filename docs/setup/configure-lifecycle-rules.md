# Configuring Lifecycle Rules

This guide explains how to configure lifecycle rules for Azure File Storage management.

## Configuration File Location

The configuration file (`lifecycle-rules.json`) can be stored:
1. In Azure Blob Storage (recommended for production)
2. Locally for testing

## Configuration Structure

### Global Settings

```json
{
    "globalSettings": {
        "dryRun": false,
        "logLevel": "Information",
        "auditLogStorageAccount": "yourstorageaccount",
        "auditLogContainer": "audit-logs",
        "fileInventoryContainer": "file-inventory",
        "retainAuditLogsDays": 90,
        "maxParallelOperations": 10,
        "excludePatterns": ["*.tmp", "~$*", ".DS_Store", "Thumbs.db"]
    }
}
```

| Setting | Type | Description |
|---------|------|-------------|
| `dryRun` | boolean | When true, no actual operations are performed |
| `logLevel` | string | Logging verbosity: Debug, Information, Warning, Error |
| `auditLogStorageAccount` | string | Storage account for audit logs |
| `auditLogContainer` | string | Container name for audit CSV files |
| `fileInventoryContainer` | string | Container for file inventory reports |
| `retainAuditLogsDays` | integer | Days to retain audit logs |
| `maxParallelOperations` | integer | Maximum concurrent operations |
| `excludePatterns` | array | File patterns to always exclude |

### Storage Accounts

Define each storage account to be managed:

```json
{
    "storageAccounts": [
        {
            "name": "mystorageaccount",
            "resourceGroup": "my-resource-group",
            "subscriptionId": "00000000-0000-0000-0000-000000000000",
            "enabled": true,
            "fileShares": [...]
        }
    ]
}
```

| Setting | Type | Description |
|---------|------|-------------|
| `name` | string | Storage account name |
| `resourceGroup` | string | Resource group containing the account |
| `subscriptionId` | GUID | Azure subscription ID |
| `enabled` | boolean | Enable/disable processing |
| `fileShares` | array | File shares to process |

### File Shares

Configure each file share with specific rules:

```json
{
    "fileShares": [
        {
            "name": "myfileshare",
            "enabled": true,
            "rules": [...]
        }
    ]
}
```

### Rules

Rules define what actions to take on matching files:

```json
{
    "rules": [
        {
            "name": "DeleteOldTempFiles",
            "enabled": true,
            "action": "delete",
            "conditions": {
                "lastModifiedDaysAgo": 30,
                "pathPrefix": "temp/",
                "fileExtensions": [".tmp", ".bak"]
            }
        }
    ]
}
```

| Setting | Type | Description |
|---------|------|-------------|
| `name` | string | Rule name for identification |
| `enabled` | boolean | Enable/disable rule |
| `action` | string | Action: `delete`, `moveToCool`, `moveToArchive` |
| `conditions` | object | Conditions that must match |

### Available Conditions

| Condition | Type | Description |
|-----------|------|-------------|
| `lastModifiedDaysAgo` | integer | Minimum days since last modification |
| `lastAccessedDaysAgo` | integer | Minimum days since last access |
| `createdDaysAgo` | integer | Minimum days since creation |
| `pathPrefix` | string | Path must start with this prefix |
| `pathSuffix` | string | Path must end with this suffix |
| `fileExtensions` | array | File must have one of these extensions |
| `minSizeBytes` | integer | Minimum file size in bytes |
| `maxSizeBytes` | integer | Maximum file size in bytes |

## Common Rule Examples

### 1. Delete Temporary Files Older Than 7 Days

```json
{
    "name": "CleanupTempFiles",
    "enabled": true,
    "action": "delete",
    "conditions": {
        "lastModifiedDaysAgo": 7,
        "fileExtensions": [".tmp", ".temp", "~$*"]
    }
}
```

### 2. Move Large Old Documents to Cool Storage

```json
{
    "name": "ArchiveLargeOldDocs",
    "enabled": true,
    "action": "moveToCool",
    "conditions": {
        "lastModifiedDaysAgo": 180,
        "fileExtensions": [".doc", ".docx", ".pdf", ".xlsx"],
        "minSizeBytes": 10485760
    }
}
```

### 3. Archive Files Over 1 Year Old

```json
{
    "name": "ArchiveOldFiles",
    "enabled": true,
    "action": "moveToArchive",
    "conditions": {
        "lastModifiedDaysAgo": 365,
        "pathPrefix": "documents/"
    }
}
```

### 4. Delete Build Artifacts

```json
{
    "name": "CleanupBuilds",
    "enabled": true,
    "action": "delete",
    "conditions": {
        "lastModifiedDaysAgo": 30,
        "pathPrefix": "builds/",
        "fileExtensions": [".dll", ".exe", ".pdb", ".obj"]
    }
}
```

### 5. Delete Log Files Older Than 90 Days

```json
{
    "name": "CleanupLogs",
    "enabled": true,
    "action": "delete",
    "conditions": {
        "lastModifiedDaysAgo": 90,
        "fileExtensions": [".log", ".txt"],
        "pathPrefix": "logs/"
    }
}
```

### 6. Archive Backup Files

```json
{
    "name": "ArchiveBackups",
    "enabled": true,
    "action": "moveToArchive",
    "conditions": {
        "lastModifiedDaysAgo": 30,
        "fileExtensions": [".bak", ".zip", ".7z"],
        "pathPrefix": "backups/"
    }
}
```

## Rule Processing Order

Rules are processed in the order they appear in the configuration. Consider this when designing rules:

1. More specific rules should come first
2. Delete rules should typically be after archive rules
3. Use `enabled: false` to temporarily disable rules

## Testing Configuration

### Validate JSON Syntax

```powershell
# Test JSON validity
$configPath = "./config/lifecycle-rules.json"
try {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    Write-Host "Configuration is valid JSON" -ForegroundColor Green
} catch {
    Write-Host "Invalid JSON: $_" -ForegroundColor Red
}
```

### Dry Run Testing

Always test with `dryRun: true` first:

```json
{
    "globalSettings": {
        "dryRun": true,
        ...
    }
}
```

Or use the `-DryRun` parameter when running the runbook:

```powershell
.\AzureFileStorageLifecycle.ps1 -ConfigurationPath ".\config\lifecycle-rules.json" -DryRun
```

## Best Practices

1. **Start Conservative**: Begin with longer retention periods and gradually reduce
2. **Use Dry Run**: Always test rules in dry run mode first
3. **Review Audit Logs**: Check audit logs after each run to verify behavior
4. **Exclude Critical Paths**: Use `excludePatterns` for files that should never be processed
5. **Monitor Disk Space**: Track storage savings over time
6. **Version Control**: Keep configuration in source control
7. **Document Rules**: Use descriptive rule names that explain the purpose

## Troubleshooting

### Rules Not Matching Files

1. Check path prefix - ensure it matches the actual file paths
2. Verify file extensions include the dot (`.tmp` not `tmp`)
3. Check date conditions - files may be newer than expected

### Too Many Files Matching

1. Add more specific conditions
2. Use `pathPrefix` to limit scope
3. Increase `lastModifiedDaysAgo` threshold

### Performance Issues

1. Reduce `maxParallelOperations` if experiencing throttling
2. Process fewer storage accounts per run
3. Split large file shares into multiple rules with path prefixes
