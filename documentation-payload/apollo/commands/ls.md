+++
title = "ls"
chapter = false
weight = 103
hidden = false
+++

## Summary
Lists files and directories in a specified path, including file permissions, timestamps, and extended attributes. Supports both local and UNC paths with concurrent file processing and chunked responses.

- **Needs Admin:** False
- **Version:** 3
- **Author:** @djhohnstein

### Arguments
- **path** (String) - Directory or file path to list (defaults to current directory). Supports UNC paths like `\\DC01\C$`

## Usage
```
ls [path]
ls \\DC01\C$
```

**Raw Output:**
```json
{
  "host": "CLIENT01",
  "is_file": false,
  "name": "Users",
  "parent_path": "C:\\",
  "files": [
    {
      "name": "Administrator",
      "size": 0,
      "is_file": false,
      "permissions": [...],
      "creation_date": "2023-01-01T12:00:00Z"
    }
  ]
}
```

**Formatted Output:**
![ls from command line](../images/ls01.png)

When clicking on the three-users icon under the "Permissions" tab, you'll see the associated ACLs for that file.

![ACLs for an object](../images/ls02.png)

This command is also integrated into the Mythic file browser.

![File browser](../images/filebrowser.png)

## Detailed Summary

### Agent Execution Flow

#### 1. Parameter Processing
```csharp
[DataContract]
internal struct LsParameters
{
    [DataMember(Name = "host")]
    public string Host;
    [DataMember(Name = "path")]
    public string Path;
}

LsParameters parameters = _jsonSerializer.Deserialize<LsParameters>(_data.Parameters);
```
- Deserializes path and optional host parameters
- Handles localhost aliases (localhost, 127.0.0.1, COMPUTERNAME)
- Constructs UNC path when host specified

#### 2. Path Resolution
```csharp
string uncPath = string.IsNullOrEmpty(host) ? parameters.Path : $@"\\{host}\{parameters.Path}";
if (ApolloInterop.Utils.PathUtils.TryGetExactPath(uncPath, out uncPath))
{
    // Path resolution successful
}
```
- Builds UNC path format for remote hosts
- Uses `TryGetExactPath` for case-sensitive path resolution
- Defaults to current directory if no path specified

#### 3. Host Detection
```csharp
if (string.IsNullOrEmpty(host))
{
    string cwd = System.IO.Directory.GetCurrentDirectory().ToString();
    if (cwd.StartsWith("\\\\"))
    {
        var hostPieces = cwd.Split('\\');
        host = hostPieces[2];
    } else
    {
        host = Environment.GetEnvironmentVariable("COMPUTERNAME");
    }
}
```
- Automatically detects host from current working directory
- Extracts hostname from UNC paths
- Falls back to local computer name

#### 4. File vs Directory Handling

##### Single File Processing
```csharp
if (File.Exists(uncPath))
{
    var tmp = new FileInfo(uncPath);
    FileInformation finfo = new FileInformation(tmp, null);
    results.IsFile = true;
    results.Permissions = GetPermissions(tmp);
}
```
- Creates `FileInfo` object for single file
- Extracts file metadata and permissions
- Sets `IsFile` flag in response

##### Directory Processing
```csharp
if (Directory.Exists(uncPath))
{
    DirectoryInfo dinfo = new DirectoryInfo(uncPath);
    string[] directories = Directory.GetDirectories(uncPath);
    string[] dirFiles = Directory.GetFiles(uncPath);
    
    TT.ParallelOptions po = new TT.ParallelOptions();
    po.MaxDegreeOfParallelism = 2;
    TT.Parallel.ForEach(directories, po, (dir) => {
        // Process directories concurrently
    });
}
```
- Enumerates subdirectories and files separately
- Uses parallel processing with degree of parallelism = 2
- Processes directories and files concurrently

#### 5. Permission Extraction
```csharp
private static ACE[] GetPermissions(FileInfo fi)
{
    List<ACE> permissions = new List<ACE>();
    FileSecurity fsec = fi.GetAccessControl(AccessControlSections.Access);
    foreach (FileSystemAccessRule FSAR in fsec.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
    {
        var tmp = GetAceInformation(FSAR);
        permissions.Add(tmp);
    }
    return permissions.ToArray();
}
```
- Retrieves file security descriptor using `GetAccessControl`
- Extracts Access Control Entries (ACEs)
- Converts to `NTAccount` format for readable names
- Handles both files and directories

#### 6. Chunked Response Processing
```csharp
private class FileDataStream
{
    public ConcurrentQueue<FileInformation> FileQueue = new ConcurrentQueue<FileInformation>();
    public event EventHandler FileChunkReached;
    
    public void Add(FileInformation item)
    {
        FileQueue.Enqueue(item);
        if (FileQueue.Count >= _chunkSize)
            FileChunkReached?.Invoke(this, null);
    }
}
```
- Uses concurrent queue for thread-safe file collection
- Triggers chunk events when reaching size threshold (10 files)
- Sends intermediate responses for large directories

### Data Structures

#### FileInformation
```csharp
struct FileInformation
{
    public string Name;
    public long Size;
    public bool IsFile;
    public string FullName;
    public DateTime CreationDate;
    public DateTime ModifyTime;
    public DateTime AccessTime;
    public ACE[] Permissions;
    public string Owner;
}
```

#### ACE (Access Control Entry)
```csharp
struct ACE
{
    public string Account;      // User/group name
    public string Type;         // Allow/Deny
    public string Rights;       // File system rights
    public bool IsInherited;    // Inherited from parent
}
```

#### FileBrowser Response
```csharp
struct FileBrowser
{
    public string Host;
    public bool IsFile;
    public string Name;
    public string ParentPath;
    public DateTime CreationDate;
    public DateTime AccessTime;
    public DateTime ModifyTime;
    public long Size;
    public ACE[] Permissions;
    public FileInformation[] Files;
    public bool Success;
}
```

### Concurrent Processing
- **Parallel Directory Processing**: Processes subdirectories using `Parallel.ForEach`
- **Parallel File Processing**: Processes files concurrently with cancellation support
- **Chunked Responses**: Sends intermediate results for large directories
- **Thread Safety**: Uses `ConcurrentQueue` for thread-safe file collection

### Error Handling
```csharp
catch (Exception ex)
{
    bRet = false;
    errorMessage = $"Failed to get information on directory {uncPath}: {ex.Message}\n\n{ex.StackTrace}";
}
```
- Catches permission denied exceptions gracefully
- Provides detailed error messages with stack traces
- Continues processing remaining files on individual failures

## APIs Used
| API | Purpose | Namespace |
|-----|---------|-----------|
| `File.Exists()` | Check if path is a file | System.IO |
| `Directory.Exists()` | Check if path is a directory | System.IO |
| `FileInfo.GetAccessControl()` | Get file security descriptor | System.IO |
| `DirectoryInfo.GetAccessControl()` | Get directory security descriptor | System.IO |
| `Directory.GetDirectories()` | Enumerate subdirectories | System.IO |
| `Directory.GetFiles()` | Enumerate files | System.IO |
| `Parallel.ForEach()` | Concurrent processing | System.Threading.Tasks |

## MITRE ATT&CK Mapping
- **T1083** - File and Directory Discovery
- **T1106** - Native API

## Security Considerations
- **Information Disclosure**: Reveals file system structure and permissions
- **Access Patterns**: Creates predictable file access patterns
- **Performance Impact**: Large directories may cause system load
- **Detection Vectors**: File enumeration may trigger security monitoring

## Limitations
1. Requires read permissions on target directories
2. Large directories may cause performance impact
3. UNC paths require network connectivity and credentials
4. Some system directories may be restricted
5. Parallel processing limited to degree of parallelism = 2

## Error Conditions
- **Access Denied**: Insufficient permissions for path or individual files
- **Path Not Found**: Specified path doesn't exist
- **Network Unreachable**: UNC path host not accessible
- **Invalid Path**: Malformed or invalid path format
- **Cancellation**: Operation cancelled during processing