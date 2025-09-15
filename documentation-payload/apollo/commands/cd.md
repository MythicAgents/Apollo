+++
title = "cd"
chapter = false
weight = 103
hidden = false
+++

## Summary
The `cd` function changes the Apollo agent's current working directory to a specified directory path. This command affects the working directory for all subsequent file system operations and supports both absolute and relative paths, including common relative identifiers like `..` for parent directory navigation. The command validates directory existence before changing and updates the Mythic callback with the new working directory.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
- **path** (String) - Directory path to change to
  - **CLI Name:** Path
  - **Display Name:** Path to Directory
  - **Description:** Directory to change to

## Usage
### Example 1: Absolute Path Navigation
**Command:**
```
cd -Path C:\Users
cd C:\Users
```
**Output:**
```text
Working directory set to C:\Users
```

### Example 2: Root Directory Navigation
**Command:**
```
cd C:\
```
**Output:**
```text
Working directory set to C:\
```

### Example 3: Relative Path Navigation
**Command:**
```
cd ..
```
**Output:**
```text
Working directory set to C:\
```

### Example 4: Directory with Spaces
**Command:**
```
cd "C:\Program Files"
cd 'C:\Program Files'
```
**Output:**
```text
Working directory set to C:\Program Files
```

### Example 5: Directory Not Found
**Command:**
```
cd C:\NonExistentDirectory
```
**Output:**
```text
Error: Directory C:\NonExistentDirectory does not exist
```

### Example 6: Relative Navigation Examples
**Command:**
```
cd ..\Windows\System32
cd .\Logs
cd ..\..\Users
```
**Output:**
```text
Working directory set to C:\Windows\System32
Working directory set to C:\Program Files\Application\Logs
Working directory set to C:\Users
```

## Detailed Summary

The `cd` function implements a straightforward directory navigation system that manages the agent's current working directory state:

### 1. Parameter Processing and Validation

The function uses a simple parameter structure for directory paths:

```csharp
[DataContract]
public struct CdParameters
{
    [DataMember(Name = "path")] public string Path;
}
```

**Parameter Processing**:
* **JSON Deserialization**: Uses `CdParameters` structure to extract the target directory path
* **Path Validation**: Checks directory existence using `Directory.Exists()` before attempting to change
* **Error Handling**: Returns specific error message if the target directory does not exist

### 2. Core Implementation

The C# implementation is straightforward and synchronous:

```csharp
public override void Start()
{
    CdParameters parameters = _jsonSerializer.Deserialize<CdParameters>(_data.Parameters);
    if (!Directory.Exists(parameters.Path))
    {
        _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
            $"Directory {parameters.Path} does not exist",
            true,
            "error"));
    }
    else
    {
        Directory.SetCurrentDirectory(parameters.Path);
        var currentPath = Directory.GetCurrentDirectory();
        _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
            $"Working directory set to {Directory.GetCurrentDirectory()}",
            true, "",
            new IMythicMessage[]
            {
                new CallbackUpdate{  Cwd =currentPath }
            }
            ));
    }
}
```

**Implementation Details**:
* **Directory Validation**: Uses `Directory.Exists()` to verify target directory exists
* **Directory Change**: Uses `Directory.SetCurrentDirectory()` to change the working directory
* **Confirmation**: Uses `Directory.GetCurrentDirectory()` to get the actual new working directory
* **Callback Update**: Sends `CallbackUpdate` message to update Mythic with new working directory

### 3. Working Directory Management

The command affects the global state of the Apollo agent:

**State Changes**:
* **Process Working Directory**: Changes the current working directory for the entire Apollo process
* **Global Impact**: Affects all subsequent file system operations that use relative paths
* **Persistent Change**: The directory change persists until another `cd` command or agent restart
* **Thread Safety**: Uses .NET's built-in thread-safe directory operations

### 4. Mythic Integration and Callback Updates

The command integrates with Mythic's callback management system:

```csharp
new IMythicMessage[]
{
    new CallbackUpdate{  Cwd =currentPath }
}
```

**Integration Features**:
* **Callback Update**: Sends `CallbackUpdate` message with new current working directory
* **UI Synchronization**: Updates Mythic's UI to reflect the agent's new working directory
* **State Persistence**: Mythic maintains the current directory state for display and reference
* **Confirmation Response**: Provides both success message and directory confirmation

### 5. Path Handling and Resolution

The system handles various path formats and types:

**Supported Path Types**:
* **Absolute Paths**: Full paths starting from drive root (e.g., `C:\Windows\System32`)
* **Relative Paths**: Paths relative to current directory (e.g., `Subdirectory`, `.\Folder`)
* **Parent Directory**: Navigate up using `..` (e.g., `..`, `..\..`, `..\OtherFolder`)
* **Current Directory**: Reference current directory using `.` (though rarely needed)

**Path Resolution**:
* **.NET Path Resolution**: Leverages .NET's built-in path resolution for relative paths
* **Drive Changes**: Can change to different drives if accessible
* **UNC Path Support**: Supports UNC paths to network locations (e.g., `\\server\share`)
* **Long Path Support**: Inherits .NET Framework's path length limitations and support

### 6. Error Handling and Validation

The implementation includes specific error handling for common scenarios:

**Error Scenarios**:
* **Directory Not Found**: Returns `"Directory {path} does not exist"` error message
* **Access Denied**: .NET will throw exceptions for inaccessible directories
* **Invalid Paths**: .NET handles invalid path format validation
* **Network Issues**: UNC path failures are handled by underlying .NET exceptions

**Validation Process**:
1. **Parameter Deserialization**: Extracts path from JSON parameters
2. **Existence Check**: Verifies directory exists using `Directory.Exists()`
3. **Change Attempt**: Uses `Directory.SetCurrentDirectory()` for actual change
4. **Confirmation**: Gets actual current directory for response

### 7. Command Line Parsing Flexibility

The Python handler provides flexible path input handling:

```python
async def parse_arguments(self):
    if len(self.command_line) == 0:
        raise Exception("Require path to change directory to.\nUsage:\n\t{}".format(CdCommand.help_cmd))
    if self.command_line[0] == "{":
        self.load_args_from_json_string(self.command_line)
    else:
        if self.command_line[0] == '"' and self.command_line[-1] == '"':
            self.command_line = self.command_line[1:-1]
        elif self.command_line[0] == "'" and self.command_line[-1] == "'":
            self.command_line = self.command_line[1:-1]    
        self.add_arg("path", self.command_line)
```

**Parsing Features**:
* **Quote Removal**: Automatically removes surrounding double or single quotes from paths
* **JSON Support**: Accepts JSON-formatted parameters
* **Error Handling**: Provides usage information when no path is provided
* **Direct Path Support**: Accepts directory path directly without parameter flags
* **Space Handling**: Properly handles paths with spaces through quote removal

### 8. Response and Display Management

The command provides clear feedback about directory changes:

**Success Response Format**:
```csharp
$"Working directory set to {Directory.GetCurrentDirectory()}"
```

**Error Response Format**:
```csharp
$"Directory {parameters.Path} does not exist"
```

**Response Characteristics**:
* **Confirmation Message**: Shows the actual directory that was set (may differ from input due to path resolution)
* **Error Specificity**: Provides specific error message indicating the problematic path
* **Status Indicators**: Uses appropriate success/error status flags
* **Display Parameters**: Shows the input path in Mythic's task display

### 9. Security and Access Control

The command respects Windows file system security:

**Security Considerations**:
* **Access Control Lists**: Respects Windows ACLs and directory permissions
* **User Context**: Operates within the security context of the Apollo agent process
* **Network Access**: Can access network paths if the agent has appropriate credentials
* **Privilege Requirements**: May require specific privileges for certain system directories

### 10. Impact on Other Commands

The directory change affects subsequent file system operations:

**Affected Commands**:
* **File Operations**: Commands like `cat`, `ls`, `upload`, `download` use relative paths from new directory
* **Process Creation**: Commands that spawn processes inherit the new working directory
* **Script Execution**: PowerShell and other script executions start from new directory
* **Path Resolution**: All relative path references resolve from the new working directory

## MITRE ATT&CK Mapping
- **T1083** - File and Directory Discovery

## Technical Deep Dive

### .NET Directory Operations

The `cd` command leverages .NET Framework's directory management capabilities:

#### Directory.SetCurrentDirectory()
```csharp
Directory.SetCurrentDirectory(parameters.Path);
```

**Method Characteristics**:
- **Process-Wide**: Changes working directory for entire process, not just current thread
- **Exception Handling**: Throws exceptions for invalid paths, access denied, etc.
- **Path Resolution**: Automatically resolves relative paths and normalizes the result
- **Thread Safety**: Method is thread-safe and atomic

#### Directory.GetCurrentDirectory()
```csharp
var currentPath = Directory.GetCurrentDirectory();
```

**Confirmation Features**:
- **Actual Path**: Returns the actual resolved path, which may differ from input path
- **Normalized Format**: Returns path in normalized Windows format
- **Drive Information**: Includes drive letter and full path information
- **Real-Time**: Returns current state at time of call

### Path Resolution Behavior

The .NET Framework handles various path resolution scenarios:

#### Relative Path Resolution
- **Single Dot (.)**: References current directory (rarely used with cd)
- **Double Dot (..)**: References parent directory
- **Subdirectory**: Direct subdirectory name resolves from current location
- **Complex Relative**: Paths like `..\..\Windows` are fully resolved

#### Drive and UNC Path Handling
- **Drive Changes**: Can change to different drives (C:, D:, etc.)
- **UNC Paths**: Supports network paths (\\server\share\folder)
- **Path Validation**: Validates path format before attempting change
- **Access Verification**: Checks access permissions during change attempt

### Error Handling Patterns

The command implements a validation-first approach:

#### Pre-Change Validation
```csharp
if (!Directory.Exists(parameters.Path))
{
    // Error response
}
```

**Validation Benefits**:
- **Early Error Detection**: Catches non-existent directories before attempting change
- **Cleaner Error Messages**: Provides specific error message for directory existence
- **Resource Efficiency**: Avoids exception handling for common error case
- **User Experience**: Immediate feedback for invalid directories

#### Exception Scenarios
While not explicitly shown in the code, `Directory.SetCurrentDirectory()` can throw:
- **DirectoryNotFoundException**: Directory path is invalid
- **SecurityException**: Insufficient permissions to access directory
- **ArgumentException**: Path contains invalid characters
- **PathTooLongException**: Path exceeds system limits

### Performance Characteristics

The `cd` command has minimal performance impact:

#### Operation Timing
- **Fast Execution**: Directory operations are typically very fast
- **Synchronous**: Operation completes before returning (no async overhead)
- **Single System Call**: Primary operation is one system call to change directory
- **Minimal Memory**: Very low memory footprint

#### System Impact
- **No File I/O**: Only changes process state, doesn't read/write files
- **Registry Access**: May involve registry access for drive mapping resolution
- **Network Latency**: UNC paths may involve network round-trips
- **Cache Effects**: May affect file system cache behavior for subsequent operations

## APIs Used and Their Purposes
| API | Purpose | DLL | Documentation |
|------|---------|-----|--------------|
| `Directory.Exists()` | Validates directory existence before changing | mscorlib.dll | [Directory.Exists](https://docs.microsoft.com/en-us/dotnet/api/system.io.directory.exists) |
| `Directory.SetCurrentDirectory()` | Changes process working directory | mscorlib.dll | [Directory.SetCurrentDirectory](https://docs.microsoft.com/en-us/dotnet/api/system.io.directory.setcurrentdirectory) |
| `Directory.GetCurrentDirectory()` | Gets current working directory path | mscorlib.dll | [Directory.GetCurrentDirectory](https://docs.microsoft.com/en-us/dotnet/api/system.io.directory.getcurrentdirectory) |
| `JsonSerializer.Deserialize<T>()` | Deserializes JSON task parameters | Apollo Agent | Internal Apollo JSON serialization |

## Security Considerations

### Access Control and Permissions
1. **Windows ACLs**: Respects file system access control lists
2. **User Context**: Limited by the privileges of the Apollo agent process
3. **Network Authentication**: UNC paths require appropriate network credentials
4. **System Directories**: Some directories may require elevated privileges

### Operational Security
1. **Directory Enumeration**: Successful directory changes reveal file system structure
2. **Access Patterns**: Directory navigation patterns may indicate reconnaissance activity
3. **Network Discovery**: UNC path usage may reveal network topology
4. **Privilege Indication**: Successful access to restricted directories indicates privilege level

### Audit and Detection
1. **File System Auditing**: Directory access may be logged by Windows audit policies
2. **Process Monitoring**: Working directory changes can be monitored by security tools
3. **Network Access**: UNC path access generates network authentication events
4. **Behavioral Analysis**: Navigation patterns may trigger behavioral detection

### Defensive Considerations
1. **Access Monitoring**: Monitor for unusual directory access patterns
2. **Privilege Escalation**: Watch for access to typically restricted directories
3. **Network Indicators**: UNC path access from workstations may be suspicious
4. **Timeline Analysis**: Correlate directory changes with other malicious activities

## Limitations

1. **Path Length Limits**: Subject to Windows maximum path length restrictions
2. **Permission Requirements**: Cannot access directories without appropriate permissions
3. **Network Dependencies**: UNC paths require network connectivity and credentials
4. **Process Scope**: Only changes working directory for the Apollo agent process
5. **No Bookmark Support**: Cannot save or return to previous directories automatically
6. **Single Directory**: Cannot change to multiple directories simultaneously
7. **No Directory Stack**: No built-in support for directory history or stack operations

## Troubleshooting

### Common Issues and Solutions

| Issue | Possible Causes | Solutions |
|-------|----------------|-----------|
| "Directory does not exist" | Incorrect path, directory deleted | Verify path with `ls` command, check spelling |
| Access denied errors | Insufficient permissions | Run with elevated privileges or check directory ACLs |
| UNC path failures | Network connectivity, credentials | Verify network access and authentication |
| Path too long errors | Windows path length limits | Use shorter paths or UNC path alternatives |
| Drive not accessible | Unmapped network drives, disconnected media | Verify drive mapping and media connectivity |

### Debugging Steps
1. **Verify Current Directory**: Use `pwd` to confirm current location
2. **List Available Directories**: Use `ls` to see accessible directories
3. **Test with Simple Paths**: Start with basic absolute paths before trying complex relative paths
4. **Check Permissions**: Verify access to target directory with `ls` on parent directory
5. **Network Diagnostics**: For UNC paths, verify network connectivity and credentials

### Best Practices
1. **Path Quoting**: Quote paths containing spaces or special characters
2. **Absolute Paths**: Use absolute paths when unsure about current location
3. **Incremental Navigation**: Navigate step-by-step for complex relative paths
4. **Permission Awareness**: Understand privilege requirements for target directories
5. **Network Path Testing**: Test UNC paths with simple operations before complex tasks

## References

- [.NET Directory Class](https://docs.microsoft.com/en-us/dotnet/api/system.io.directory)
- [Windows File System Paths](https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
- [File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [Windows Working Directory](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setcurrentdirectory)
- [Apollo Agent Source Code](https://github.com/MythicAgents/Apollo)