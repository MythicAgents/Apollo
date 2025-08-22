+++
title = "net_shares"
chapter = false
weight = 103
hidden = false
+++

## Summary
Enumerates network shares on a specified computer using `NetShareEnum` Win32 API. Tests share accessibility and categorizes share types including disk drives, print queues, and IPC shares.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
- **computer** (Optional String) - Target computer name (defaults to localhost)

## Usage
```
net_shares
net_shares client01.lab.local
```

**Raw Output:**
```json
[
  {
    "computer_name": "CLIENT01",
    "share_name": "C$",
    "comment": "Default share",
    "type": "Special Reserved for IPC",
    "readable": false
  }
]
```

**Formatted Output:**
![net_shares](../images/net_shares.png)

## Detailed Summary

### Agent Execution Flow

#### 1. API Function Resolution
```csharp
public net_shares(IAgent agent, ApolloInterop.Structs.MythicStructs.MythicTask data) : base(agent, data)
{
    _pNetApiBufferFree = _agent.GetApi().GetLibraryFunction<NetApiBufferFree>(Library.NETUTILS, "NetApiBufferFree");
    _pNetShareEnum = _agent.GetApi().GetLibraryFunction<NetShareEnum>(Library.SRVCLI, "NetShareEnum");
}
```
- Resolves `NetShareEnum` from SRVCLI library
- Resolves `NetApiBufferFree` from NETUTILS library
- Uses Apollo's dynamic API resolution framework

#### 2. Parameter Processing
```csharp
[DataContract]
public struct NetSharesParameters
{
    [DataMember(Name = "computer")] public string Computer;
}

NetSharesParameters parameters = _jsonSerializer.Deserialize<NetSharesParameters>(_data.Parameters);
string computer = parameters.Computer;
if (string.IsNullOrEmpty(computer))
{
    computer = Environment.GetEnvironmentVariable("COMPUTERNAME");
}
```
- Deserializes computer parameter
- Defaults to local computer name if not specified

#### 3. Share Enumeration
```csharp
private ShareInfo[] EnumerateShares(string computer)
{
    int entriesread = 0;
    int totalentries = 0;
    int resume_handle = 0;
    IntPtr bufPtr = IntPtr.Zero;
    int ret = _pNetShareEnum(computer, 1, ref bufPtr, 0xFFFFFFFF, ref entriesread, ref totalentries, ref resume_handle);
}
```
- Calls `NetShareEnum` with level 1 for basic share information
- Uses maximum preferred length (0xFFFFFFFF) for buffer allocation
- Returns enumeration result code and share count

#### 4. Share Structure Processing
```csharp
if (ret == 0)
{
    IntPtr currentPtr = bufPtr;
    for (int i = 0; i < entriesread; i++)
    {
        ShareInfo shi1 = (ShareInfo)Marshal.PtrToStructure(currentPtr, typeof(ShareInfo));
        ShareInfos.Add(shi1);
        currentPtr = (IntPtr)(currentPtr.ToInt64() + nStructSize);
    }
    _pNetApiBufferFree(bufPtr);
}
```
- Iterates through buffer entries using pointer arithmetic
- Marshals each structure from unmanaged memory
- Advances pointer by structure size for next entry
- Frees buffer memory after processing

#### 5. Share Accessibility Testing
```csharp
try
{
    string path = String.Format("\\\\{0}\\{1}", computer, share.shi1_netname);
    var files = System.IO.Directory.GetFiles(path);
    result.Readable = true;
}
catch
{
    result.Readable = false;
}
```
- Constructs UNC path for each share
- Attempts to list files using `Directory.GetFiles()`
- Sets readable flag based on access success/failure
- Handles permission exceptions gracefully

#### 6. Share Type Classification
```csharp
switch (share.shi1_type)
{
    case ShareType.STYPE_DISKTREE:
        result.Type = "Disk Drive";
        break;
    case ShareType.STYPE_PRINTQ:
        result.Type = "Print Queue";
        break;
    case ShareType.STYPE_DEVICE:
        result.Type = "Communication Device";
        break;
    case ShareType.STYPE_IPC:
        result.Type = "Interprocess Communication (IPC)";
        break;
    case ShareType.STYPE_SPECIAL:
        result.Type = "Special Reserved for IPC.";
        break;
    // Additional share types...
}
```
- Maps share type enumeration to human-readable descriptions
- Handles standard Windows share types
- Provides fallback for unknown share types

### Data Structures

#### ShareInfo (Unmanaged)
```csharp
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct ShareInfo
{
    public string shi1_netname;  // Share name
    public ShareType shi1_type;  // Share type enumeration
    public string shi1_remark;   // Share comment/description
}
```

#### NetShareInformation (Managed)
```csharp
struct NetShareInformation
{
    public string ComputerName;  // Target computer name
    public string ShareName;     // Network share name
    public string Comment;       // Share description
    public string Type;         // Human-readable share type
    public bool Readable;       // Access test result
}
```

#### ShareType Enumeration
```csharp
public enum ShareType : uint
{
    STYPE_DISKTREE = 0,          // Disk drive share
    STYPE_PRINTQ = 1,            // Print queue share
    STYPE_DEVICE = 2,            // Communication device
    STYPE_IPC = 3,               // IPC share
    STYPE_SPECIAL = 0x80000000,  // Administrative shares
    STYPE_CLUSTER_FS = 0x02000000,     // Cluster file system
    STYPE_CLUSTER_SOFS = 0x04000000,   // Scale-out file system
    STYPE_CLUSTER_DFS = 0x08000000,    // DFS share in cluster
    STYPE_TEMPORARY = 0x40000000,      // Temporary share
    STYPE_UNKNOWN = 10,          // Unknown type
}
```

### Win32 API Integration

#### NetShareEnum Function
```csharp
private delegate int NetShareEnum(
    [MarshalAs(UnmanagedType.LPWStr)] string serverName,
    int level,
    ref IntPtr bufPtr,
    uint prefmaxlen,
    ref int entriesread,
    ref int totalentries,
    ref int resume_handle);
```
- **serverName**: Target computer name
- **level**: Information level (1 for basic share info)
- **bufPtr**: Receives buffer pointer
- **prefmaxlen**: Preferred maximum buffer length
- **entriesread**: Number of entries returned
- **totalentries**: Total entries available
- **resume_handle**: Continuation handle

### Browser Interface Integration
The JavaScript processes the JSON response into an interactive table with:
- **List Button**: Launches file browser for accessible shares
- **Button State**: Disabled for non-readable shares
- **Share Details**: Name, comment, type, and accessibility
- **Dynamic Title**: Shows target computer name

### Error Handling
- **API Errors**: Captures and reports `NetShareEnum` return codes
- **Access Exceptions**: Gracefully handles share access failures
- **Memory Management**: Ensures proper buffer cleanup
- **Common Errors**:
  - **53**: Network path not found
  - **5**: Access denied

## APIs Used
| API | Purpose | DLL |
|-----|---------|-----|
| `NetShareEnum` | Enumerate network shares | srvcli.dll |
| `NetApiBufferFree` | Free allocated buffer | netutils.dll |
| `Directory.GetFiles()` | Test share accessibility | System.IO |
| `Marshal.PtrToStructure` | Convert unmanaged to managed | mscorlib.dll |

## MITRE ATT&CK Mapping
- **T1590** - Gather Victim Network Information
- **T1069** - Permission Groups Discovery

## Security Considerations
- **Information Disclosure**: Reveals available network shares and types
- **Access Testing**: Probes share accessibility which may be logged
- **Reconnaissance**: Provides attack surface information
- **Detection Vectors**: Share enumeration may trigger security monitoring

## Limitations
1. Requires network connectivity for remote computers
2. Share accessibility depends on current user's permissions
3. Some administrative shares may be hidden or restricted
4. Access testing may generate audit logs
5. Large number of shares may impact performance

## Error Conditions
- **Network Path Not Found**: Target computer unreachable
- **Access Denied**: Insufficient privileges for share enumeration
- **Invalid Computer Name**: Specified computer doesn't exist
- **RPC Server Unavailable**: Remote procedure call failures
- **Buffer Allocation**: Memory allocation failures