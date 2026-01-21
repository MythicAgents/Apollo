+++
title = "cp"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: File Open, File Write
{{% /notice %}}

## Summary
The `cp` function copies a specified file from one location to another location on the file system. This command performs a complete file copy operation, creating an exact duplicate of the source file at the destination path. The implementation includes comprehensive validation to ensure the source is a file (not a directory) and generates appropriate artifacts for both the read and write operations for audit tracking.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
- **source** (String) - Path to the source file to copy
  - **CLI Name:** Path
  - **Display Name:** Source file to copy
  - **Description:** Source file to copy
  - **Required:** True
- **destination** (String) - Path where the copied file will be created
  - **CLI Name:** Destination
  - **Display Name:** Destination path
  - **Description:** Where the new file will be created
  - **Required:** True

## Usage
### Example 1: Basic File Copy
**Command:**
```
cp -Path test1.txt -Destination test2.txt
cp test1.txt test2.txt
```
**Output:**
```text
Copied C:\CurrentPath\test1.txt to C:\CurrentPath\test2.txt
```

### Example 2: Copy to Different Directory
**Command:**
```
cp -Path C:\temp\document.txt -Destination "C:\Program Files\document.txt"
```
**Output:**
```text
Copied C:\temp\document.txt to C:\Program Files\document.txt
```

### Example 3: Copy with Quoted Paths
**Command:**
```
cp "C:\Source File.txt" "C:\Destination File.txt"
```
**Output:**
```text
Copied C:\Source File.txt to C:\Destination File.txt
```

### Example 4: Directory Copy Attempt (Error)
**Command:**
```
cp C:\MyDirectory C:\NewDirectory
```
**Output:**
```text
Error: C:\MyDirectory is a directory. Please specify a file.
```

### Example 5: File Not Found (Error)
**Command:**
```
cp nonexistent.txt destination.txt
```
**Output:**
```text
Error: Failed to copy file: Could not find file 'C:\CurrentPath\nonexistent.txt'.
```

### Example 6: Access Denied (Error)
**Command:**
```
cp C:\Windows\System32\config\SAM C:\temp\sam_copy
```
**Output:**
```text
Error: Failed to copy file: Access to the path 'C:\Windows\System32\config\SAM' is denied.
```

## Detailed Summary

The `cp` function implements a comprehensive file copying system with validation, error handling, and audit trail generation:

### 1. Parameter Processing and Structure

The function uses a dedicated parameter structure for source and destination paths:

```csharp
[DataContract]
internal struct CpParameters
{
    [DataMember(Name = "source")]
    public string SourceFile;
    [DataMember(Name = "destination")]
    public string DestinationFile;
}
```

**Parameter Structure**:
* **Source File**: The file to be copied (must be a file, not a directory)
* **Destination File**: The target location for the copied file
* **JSON Mapping**: Uses DataContract attributes for proper JSON deserialization
* **Required Fields**: Both source and destination are required parameters

### 2. Command Line Parsing Implementation

The Python handler implements sophisticated argument parsing for flexible input:

```python
def split_commandline(self):
    if self.command_line[0] == "{":
        raise Exception("split_commandline expected string, but got JSON object: " + self.command_line)
    inQuotes = False
    curCommand = ""
    cmds = []
    for x in range(len(self.command_line)):
        c = self.command_line[x]
        if c == '"' or c == "'":
            inQuotes = not inQuotes
        if not inQuotes and c == " ":
            cmds.append(curCommand)
            curCommand = ""
        else:
            curCommand += c
    # Quote removal logic...
```

**Parsing Features**:
* **Quote-Aware Splitting**: Properly handles spaces within quoted paths
* **Quote Removal**: Automatically removes surrounding quotes from parsed arguments
* **Two-Argument Validation**: Ensures exactly two arguments are provided
* **JSON Support**: Supports both command line and JSON parameter formats

### 3. Core File Copy Implementation

The main copy operation includes comprehensive validation and error handling:

```csharp
public override void Start()
{
    CpParameters parameters = _jsonSerializer.Deserialize<CpParameters>(_data.Parameters);
    MythicTaskResponse resp;
    List<IMythicMessage> artifacts = new List<IMythicMessage>();
    try
    {
        FileInfo source = new FileInfo(parameters.SourceFile);
        artifacts.Add(Artifact.FileOpen(source.FullName));
        if (source.Attributes.HasFlag(FileAttributes.Directory))
        {
            resp = CreateTaskResponse(
                $"{source.FullName} is a directory.  Please specify a file.",
                true, "error", artifacts.ToArray());
        }
        else
        {
            File.Copy(parameters.SourceFile, parameters.DestinationFile);
            FileInfo dest = new FileInfo(parameters.DestinationFile);
            artifacts.Add(Artifact.FileWrite(dest.FullName, source.Length));
            artifacts.Add(new FileBrowser(dest));
            resp = CreateTaskResponse(
                $"Copied {source.FullName} to {dest.FullName}",
                true, "completed", artifacts.ToArray());
        }
    }
    catch (Exception ex)
    {
        resp = CreateTaskResponse($"Failed to copy file: {ex.Message}", true, "error", artifacts.ToArray());
    }
}
```

**Implementation Flow**:
1. **Parameter Deserialization**: Extracts source and destination paths
2. **Source Validation**: Creates `FileInfo` object and validates it's not a directory
3. **Artifact Generation**: Creates `FileOpen` artifact for source file access
4. **File Copy Operation**: Uses `File.Copy()` to perform the actual copy
5. **Success Artifacts**: Generates `FileWrite` and `FileBrowser` artifacts for destination
6. **Error Handling**: Catches all exceptions and provides detailed error messages

### 4. Directory Detection and Validation

The implementation specifically validates that the source is a file, not a directory:

```csharp
FileInfo source = new FileInfo(parameters.SourceFile);
if (source.Attributes.HasFlag(FileAttributes.Directory))
{
    resp = CreateTaskResponse(
        $"{source.FullName} is a directory.  Please specify a file.",
        true, "error", artifacts.ToArray());
}
```

**Validation Process**:
* **FileInfo Creation**: Creates `FileInfo` object to access file attributes
* **Directory Check**: Uses `FileAttributes.Directory` flag to detect directories
* **Specific Error Message**: Provides clear error message for directory sources
* **Early Exit**: Prevents attempting to copy directories with `File.Copy()`

### 5. Artifact Generation and Tracking

The command generates multiple artifacts for comprehensive audit tracking:

**Source File Artifacts**:
```csharp
artifacts.Add(Artifact.FileOpen(source.FullName));
```

**Destination File Artifacts**:
```csharp
artifacts.Add(Artifact.FileWrite(dest.FullName, source.Length));
artifacts.Add(new FileBrowser(dest));
```

**Artifact Types**:
* **File Open**: Records access to the source file with full path
* **File Write**: Records creation of destination file with file size
* **File Browser**: Updates Mythic's file browser with the new file
* **Timeline Integration**: All artifacts are timestamped and associated with the task

### 6. File System Operations

The command uses .NET Framework's built-in file operations:

```csharp
File.Copy(parameters.SourceFile, parameters.DestinationFile);
```

**File.Copy() Characteristics**:
* **Complete Copy**: Creates exact duplicate of source file
* **Metadata Preservation**: Preserves file attributes, timestamps (creation time may change)
* **Overwrite Behavior**: Uses default overwrite behavior (will fail if destination exists)
* **Exception Handling**: Throws exceptions for various error conditions
* **Path Resolution**: Handles both absolute and relative paths

### 7. Error Handling and Exception Management

The implementation includes comprehensive error handling for various failure scenarios:

**Handled Error Types**:
* **File Not Found**: Source file doesn't exist
* **Access Denied**: Insufficient permissions for source or destination
* **Path Too Long**: Paths exceed Windows limitations
* **Disk Full**: Insufficient space for destination file
* **File In Use**: Source or destination file is locked by another process
* **Network Issues**: Problems with UNC paths or network drives

**Error Response Format**:
```csharp
resp = CreateTaskResponse($"Failed to copy file: {ex.Message}", true, "error", artifacts.ToArray());
```

### 8. Path Handling and Resolution

The system handles various path formats and scenarios:

**Supported Path Types**:
* **Absolute Paths**: Full paths from drive root (`C:\path\file.txt`)
* **Relative Paths**: Paths relative to current directory (`.\file.txt`, `subfolder\file.txt`)
* **UNC Paths**: Network paths (`\\server\share\file.txt`)
* **Mixed Scenarios**: Source and destination can use different path types

**Path Processing**:
* **FileInfo Resolution**: Uses `FileInfo` to resolve and validate paths
* **Full Path Confirmation**: Response shows fully resolved paths
* **Cross-Directory Copy**: Supports copying between different directories and drives

### 9. Display and Response Management

The command provides detailed feedback about copy operations:

**Success Response Format**:
```csharp
$"Copied {source.FullName} to {dest.FullName}"
```

**Error Response Formats**:
* Directory error: `"{path} is a directory. Please specify a file."`
* General error: `"Failed to copy file: {exception message}"`

**Display Parameters**:
```python
response.DisplayParams = "-Source {} -Destination {}".format(
    taskData.args.get_arg("source"), taskData.args.get_arg("destination")
)
```

### 10. Security and Permission Considerations

The copy operation respects file system security:

**Security Aspects**:
* **Source Permissions**: Requires read access to source file
* **Destination Permissions**: Requires write access to destination directory
* **User Context**: Operates within Apollo agent's security context
* **ACL Inheritance**: Destination file inherits ACLs from destination directory
* **Audit Generation**: Creates audit trail through artifact generation

## MITRE ATT&CK Mapping
- **T1570** - Lateral Tool Transfer

## Technical Deep Dive

### .NET File Copy Implementation

The `cp` command leverages .NET Framework's `File.Copy()` method:

#### File.Copy() Method Behavior
```csharp
File.Copy(parameters.SourceFile, parameters.DestinationFile);
```

**Method Characteristics**:
- **Atomic Operation**: Copy completes entirely or fails entirely
- **Exception-Based Error Handling**: Throws specific exceptions for different error conditions
- **Default Overwrite Behavior**: By default, fails if destination file already exists
- **Metadata Handling**: Preserves most file attributes but may update timestamps
- **Performance**: Optimized for the underlying file system (uses system-level copy operations)

#### File Attribute Checking
```csharp
if (source.Attributes.HasFlag(FileAttributes.Directory))
```

**Attribute Validation**:
- **FileAttributes Enum**: Uses Windows file attribute flags
- **Directory Detection**: Specifically checks for directory attribute
- **Multiple Attributes**: Can detect files with multiple attributes (hidden, system, etc.)
- **Performance**: Minimal overhead for attribute checking

### Command Line Parsing Algorithm

The Python handler implements a sophisticated parsing algorithm:

#### Quote-Aware Parsing
The `split_commandline()` method handles complex quoting scenarios:
- **State Tracking**: Maintains `inQuotes` state to track quote context
- **Quote Types**: Handles both single and double quotes
- **Space Handling**: Only splits on spaces outside of quotes
- **Quote Removal**: Removes quotes from final parsed arguments

#### Validation Logic
```python
if len(cmds) != 2:
    raise Exception("Invalid number of arguments given. Expected two, but received: {}")
```

**Validation Features**:
- **Exact Count**: Requires exactly two arguments (source and destination)
- **Clear Error Messages**: Provides helpful error messages with usage information
- **Flexible Input**: Supports both positional arguments and JSON format

### Artifact Generation Strategy

The command generates multiple artifacts for comprehensive tracking:

#### Artifact Types and Purposes
1. **File Open Artifact**: 
   - **Purpose**: Records access to source file
   - **Timing**: Generated before copy operation
   - **Data**: Full path of source file

2. **File Write Artifact**:
   - **Purpose**: Records creation of destination file
   - **Timing**: Generated after successful copy
   - **Data**: Full path and file size of destination

3. **FileBrowser Artifact**:
   - **Purpose**: Updates Mythic's file browser display
   - **Timing**: Generated after successful copy
   - **Integration**: Allows browsing to newly created file

### Error Handling Patterns

The command implements multiple layers of error detection:

#### Pre-Copy Validation
- **Directory Detection**: Prevents attempting to copy directories
- **FileInfo Creation**: Validates source path format and accessibility
- **Attribute Checking**: Ensures source is appropriate for copying

#### Runtime Exception Handling
- **Comprehensive Catch**: Catches all exceptions during copy operation
- **Message Preservation**: Preserves original exception messages
- **Artifact Inclusion**: Includes artifacts even in error responses for audit trail

### Performance and Resource Considerations

#### Memory Usage
- **Minimal Memory Footprint**: `File.Copy()` uses system-level operations
- **No Buffering**: No manual buffering or chunk processing required
- **Stream-Based**: Uses efficient file streams at system level

#### I/O Characteristics
- **System Call Optimization**: Leverages optimized system copy operations
- **Network Efficiency**: Efficient for network paths (UNC shares)
- **Concurrent Safety**: Thread-safe operation through system-level locking

## Common Use Cases and Examples

### 1. Configuration File Backup
```bash
# Create backups of configuration files
cp C:\Config\app.config C:\Config\app.config.bak
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
```

### 2. Log File Preservation
```bash
# Copy log files for analysis
cp C:\Logs\application.log C:\Analysis\app_log_copy.txt
cp /var/log/auth.log /tmp/auth_analysis.log
```

### 3. Tool Staging
```bash
# Stage tools in accessible locations
cp C:\Tools\tool.exe C:\Temp\legitimate_app.exe
cp /opt/tools/scanner /tmp/system_check
```

### 4. Data Exfiltration Preparation
```bash
# Copy sensitive files to staging area
cp C:\Users\admin\Documents\passwords.xlsx C:\Temp\data.xlsx
cp /home/user/.ssh/id_rsa /tmp/backup_key
```

### 5. System File Analysis
```bash
# Copy system files for offline analysis
cp C:\Windows\System32\drivers\etc\hosts C:\Analysis\hosts_copy
cp /etc/passwd /tmp/passwd_copy
```

## APIs Used and Their Purposes
| API | Purpose | DLL | Documentation |
|------|---------|-----|--------------|
| `File.Copy()` | Copies file from source to destination | mscorlib.dll | [File.Copy](https://docs.microsoft.com/en-us/dotnet/api/system.io.file.copy) |
| `FileInfo()` | Gets file information and attributes | mscorlib.dll | [FileInfo](https://docs.microsoft.com/en-us/dotnet/api/system.io.fileinfo) |
| `FileAttributes.HasFlag()` | Checks for specific file attributes | mscorlib.dll | [Enum.HasFlag](https://docs.microsoft.com/en-us/dotnet/api/system.enum.hasflag) |
| `JsonSerializer.Deserialize<T>()` | Deserializes JSON task parameters | Apollo Agent | Internal Apollo JSON serialization |

## Security Considerations

### File System Permissions
1. **Source Access**: Requires read permissions on source file
2. **Destination Access**: Requires write permissions in destination directory
3. **ACL Inheritance**: Destination file inherits security settings from target directory
4. **User Context**: Limited by Apollo agent's privilege level

### Operational Security
1. **File Access Patterns**: Copy operations may reveal reconnaissance activities
2. **Staging Behavior**: Multiple file copies may indicate tool staging
3. **Data Movement**: Large file copies may suggest data exfiltration
4. **Audit Trail**: Generates comprehensive audit artifacts

### Detection Considerations
1. **File System Monitoring**: Copy operations may trigger file system audit events
2. **Behavioral Analysis**: Unusual copy patterns may indicate malicious activity
3. **Network Monitoring**: UNC path copies generate network traffic
4. **Performance Impact**: Large file copies may affect system performance

### Defensive Implications
1. **Access Monitoring**: Monitor for copies of sensitive files
2. **Unusual Locations**: Watch for files copied to temporary or staging directories
3. **Permission Escalation**: Monitor for successful copies of restricted files
4. **Timeline Analysis**: Correlate copy operations with other suspicious activities

## Limitations

1. **File-Only Operation**: Cannot copy directories (use directory-specific commands)
2. **No Overwrite Control**: Uses default overwrite behavior of `File.Copy()`
3. **No Progress Reporting**: No progress indication for large file copies
4. **Synchronous Operation**: Blocks agent during copy operation
5. **No Resume Capability**: Cannot resume interrupted copy operations
6. **Single File Limit**: Can only copy one file per command execution
7. **Path Length Limits**: Subject to Windows maximum path length restrictions
8. **No Verification**: Does not verify integrity of copied file

## Troubleshooting

### Common Issues and Solutions

| Issue | Possible Causes | Solutions |
|-------|----------------|-----------|
| "is a directory" error | Attempting to copy a directory | Use directory-specific commands for directory operations |
| "Failed to copy file" with access denied | Insufficient permissions | Check source read and destination write permissions |
| "Could not find file" error | Incorrect source path | Verify source file exists with `ls` command |
| Path too long errors | Windows path limits | Use shorter paths or UNC alternatives |
| Destination already exists | File.Copy default behavior | Manually remove destination file first |

### Debugging Steps
1. **Verify Source File**: Use `ls` to confirm source file exists and is accessible
2. **Check Destination Directory**: Ensure destination directory exists and is writable
3. **Test Permissions**: Verify read access to source and write access to destination
4. **Path Validation**: Check for invalid characters or excessive path lengths
5. **Quote Usage**: Ensure proper quoting for paths with spaces

### Best Practices
1. **Path Quoting**: Always quote paths containing spaces or special characters
2. **Permission Verification**: Check permissions before attempting copy operations
3. **Destination Planning**: Ensure destination directory exists and has sufficient space
4. **Error Handling**: Be prepared for permission and access errors
5. **Audit Awareness**: Understand that copy operations generate audit trails

## References

- [.NET File.Copy Method](https://docs.microsoft.com/en-us/dotnet/api/system.io.file.copy)
- [FileInfo Class](https://docs.microsoft.com/en-us/dotnet/api/system.io.fileinfo)
- [File Attributes](https://docs.microsoft.com/en-us/dotnet/api/system.io.fileattributes)
- [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- [Apollo Agent Source Code](https://github.com/MythicAgents/Apollo)