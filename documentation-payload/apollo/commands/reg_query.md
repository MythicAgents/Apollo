+++
title = "reg_query"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Registry Read
{{% /notice %}}

## Summary
Queries Windows registry keys and values using `Microsoft.Win32.RegistryKey` APIs. Enumerates subkeys and values within a specified registry path, handling multiple data types and generating registry access artifacts.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
- **hive** (ChooseOne) - Registry hive (HKLM, HKCU, HKU, HKCR, HKCC)
- **key** (String, Optional) - Registry key path within the hive

## Usage
```
reg_query HKLM:\System\Setup
reg_query -Hive HKLM -Key Software\Microsoft\Windows\CurrentVersion
```

![subkeys](../images/reg_query.png)

**Raw Output:**
```json
[
  {
    "hive": "HKLM",
    "name": "SystemSetupInProgress",
    "full_name": "System\\Setup",
    "value": "0",
    "value_type": "int",
    "result_type": "value"
  },
  {
    "hive": "HKLM", 
    "name": "Upgrade",
    "full_name": "System\\Setup\\Upgrade",
    "value": "",
    "value_type": "key",
    "result_type": "key"
  }
]
```

**Formatted Output:**
![subkeys](../images/reg_query_disp.png)

## Detailed Summary

### Agent Execution Flow

#### 1. Parameter Processing
```csharp
[DataContract]
internal struct RegQueryParameters
{
    [DataMember(Name = "hive")]
    public string Hive;
    [DataMember(Name = "key")]
    public string Key;
}

RegQueryParameters parameters = _jsonSerializer.Deserialize<RegQueryParameters>(_data.Parameters);
```
- Deserializes registry hive and key path
- Supports both full and abbreviated hive names

#### 2. Subkey Enumeration
```csharp
private static string[] GetSubKeys(string hive, string subkey)
{
    using (RegistryKey regKey = RegistryUtils.GetRegistryKey(hive, subkey, false))
    {
        return regKey.GetSubKeyNames();
    }
}

string[] subkeys = GetSubKeys(parameters.Hive, parameters.Key);
foreach (string subkey in subkeys)
{
    results.Add(new RegQueryResult
    {
        Name = subkey,
        FullName = parameters.Key.EndsWith("\\") ? $"{parameters.Key}{subkey}" : $"{parameters.Key}\\{subkey}",
        Hive = parameters.Hive,
        ResultType = "key"
    });
}
```
- Uses `RegistryUtils.GetRegistryKey()` to open registry key
- Calls `GetSubKeyNames()` to enumerate child keys
- Constructs full path for each subkey
- Marks entries as "key" type

#### 3. Registry Value Enumeration
```csharp
private static string[] GetValueNames(string hive, string subkey)
{
    using (RegistryKey regKey = RegistryUtils.GetRegistryKey(hive, subkey, false))
    {
        return regKey.GetValueNames();
    }
}

string[] subValNames = GetValueNames(parameters.Hive, parameters.Key);
foreach (string valName in subValNames)
{
    tmpVal = GetValue(parameters.Hive, parameters.Key, valName);
    SetValueType(tmpVal, ref res);
    results.Add(res);
}
```
- Enumerates value names within the registry key
- Retrieves actual value data for each name
- Processes value types for proper display

#### 4. Value Type Processing
```csharp
private void SetValueType(object tmpVal, ref RegQueryResult res)
{
    if (tmpVal is String)
    {
        res.Value = string.IsNullOrEmpty(tmpVal.ToString()) ? "(value not set)" : tmpVal.ToString();
        res.Type = "string";
    }
    else if (tmpVal is int)
    {
        res.Value = tmpVal.ToString();
        res.Type = "int";
    }
    else if (tmpVal is byte[])
    {
        res.Value = BitConverter.ToString((byte[])tmpVal);
        res.Type = "byte[]";
    }
    else if (tmpVal is null)
    {
        res.Value = "(value not set)";
        res.Type = "null";
    }
    else
    {
        res.Value = tmpVal.ToString();
        res.Type = "unknown";
    }
}
```
- Handles multiple registry data types
- Converts binary data to hex string representation
- Provides fallback for unknown types

#### 5. Artifact Generation
```csharp
artifacts.Add(Artifact.RegistryRead(parameters.Hive, parameters.Key));
foreach (string valName in subValNames)
{
    artifacts.Add(Artifact.RegistryRead(parameters.Hive, $"{parameters.Key} {valName}"));
}
```
- Creates registry read artifact for each key access
- Generates separate artifacts for value reads
- Tracks all registry access operations

#### 6. Error Handling
```csharp
try
{
    string[] subkeys = GetSubKeys(parameters.Hive, parameters.Key);
}
catch (Exception ex)
{
    error = ex.Message;
}

if (results.Count == 0)
{
    resp = CreateTaskResponse(error, true, "error", artifacts.ToArray());
}
```
- Separates subkey and value enumeration errors
- Continues processing if one operation fails
- Reports errors only if no results obtained

### Registry Hive Mapping

#### Supported Hives
| Abbreviation | Full Name | Description |
|--------------|-----------|-------------|
| HKLM | HKEY_LOCAL_MACHINE | System-wide settings |
| HKCU | HKEY_CURRENT_USER | Current user settings |
| HKU | HKEY_USERS | All user profiles |
| HKCR | HKEY_CLASSES_ROOT | File associations and COM |
| HKCC | HKEY_CURRENT_CONFIG | Current hardware profile |

#### Hive Resolution
```python
hiveMap = {
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKEY_CURRENT_USER": "HKCU", 
    "HKEY_USERS": "HKU",
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKEY_CURRENT_CONFIG": "HKCC"
}
```
- Accepts both full and abbreviated hive names
- Normalizes to abbreviated format for consistency

### Data Structures

#### RegQueryResult
```csharp
struct RegQueryResult
{
    public string Hive;        // Registry hive abbreviation
    public string Name;        // Key or value name
    public string FullName;    // Complete registry path
    public string Value;       // Value data (for values)
    public string Type;        // Data type
    public string ResultType;  // "key" or "value"
}
```

### Registry Data Types

#### Supported Types
- **String**: REG_SZ and REG_EXPAND_SZ values
- **Integer**: REG_DWORD values  
- **Binary**: REG_BINARY displayed as hex
- **Null**: Empty or null values
- **Unknown**: Fallback for unsupported types

#### Binary Data Handling
```csharp
res.Value = BitConverter.ToString((byte[])tmpVal);
```
- Converts byte arrays to hex string format
- Uses hyphen-separated hex representation

### Registry Access Patterns

#### Key Enumeration
1. Open registry key with read access
2. Call `GetSubKeyNames()` to list child keys
3. Build full paths for navigation
4. Mark as "key" type results

#### Value Enumeration  
1. Open same registry key
2. Call `GetValueNames()` to list values
3. Retrieve value data with `GetValue()`
4. Process data types appropriately
5. Mark as "value" type results

## APIs Used
| API | Purpose | Namespace |
|-----|---------|-----------|
| `RegistryUtils.GetRegistryKey()` | Open registry key | Apollo Utils |
| `RegistryKey.GetSubKeyNames()` | Enumerate subkeys | Microsoft.Win32 |
| `RegistryKey.GetValueNames()` | Enumerate value names | Microsoft.Win32 |
| `RegistryKey.GetValue()` | Retrieve value data | Microsoft.Win32 |
| `BitConverter.ToString()` | Convert binary to hex | System |

## MITRE ATT&CK Mapping
- **T1012** - Query Registry
- **T1552** - Unsecured Credentials (registry stored credentials)

## Security Considerations
- **Information Disclosure**: Reveals registry structure and sensitive values
- **Credential Exposure**: May expose stored passwords or keys
- **System Configuration**: Shows security settings and configurations
- **Attack Planning**: Provides reconnaissance for privilege escalation

## Limitations
1. Access depends on current user privileges
2. Some registry keys require elevated permissions
3. Large registry trees may impact performance
4. Binary data displayed as hex strings only
5. No write or modification capabilities

## Error Conditions
- **Access Denied**: Insufficient permissions for registry key
- **Key Not Found**: Specified registry path doesn't exist
- **Invalid Hive**: Unsupported or malformed hive name
- **Path Too Long**: Registry path exceeds maximum length
- **System Error**: Underlying registry API failures

## Common Use Cases

#### System Information
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` - OS version info
- `HKLM\SYSTEM\CurrentControlSet\Services` - Service configurations
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` - Installed programs

#### User Settings
- `HKCU\Software` - User application settings
- `HKCU\Environment` - User environment variables
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` - User startup programs

#### Security Settings
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` - LSA settings
- `HKLM\SOFTWARE\Policies` - Group policy settings
- `HKCU\Software\Policies` - User policy settings