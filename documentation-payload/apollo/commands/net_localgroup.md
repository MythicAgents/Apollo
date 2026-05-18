+++
title = "net_localgroup"
chapter = false
weight = 103
hidden = false
+++

## Summary
Enumerates local groups on a specified computer using `NetLocalGroupEnum` Win32 API. Retrieves group names, comments, and generates SIDs for each local group.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
- **computer** (Optional String) - Target computer name (defaults to localhost)

## Usage
```
net_localgroup
net_localgroup client01.lab.local
```

**Raw Output:**
```json
[
  {
    "computer_name": "CLIENT01",
    "group_name": "Administrators",
    "comment": "Administrators have complete and unrestricted access",
    "sid": "S-1-5-32-544"
  }
]
```

**Formatted Output:**
![net_localgroup](../images/net_localgroup.png)

## Detailed Summary

### Agent Execution Flow

#### 1. API Function Resolution
```csharp
public net_localgroup(IAgent agent, ApolloInterop.Structs.MythicStructs.MythicTask data) : base(agent, data)
{
    _pNetLocalGroupEnum = _agent.GetApi().GetLibraryFunction<NetLocalGroupEnum>(Library.SAMCLI, "NetLocalGroupEnum");
    _pNetApiBufferFree = _agent.GetApi().GetLibraryFunction<NetApiBufferFree>(Library.NETUTILS, "NetApiBufferFree");
}
```
- Resolves `NetLocalGroupEnum` from SAMCLI library
- Resolves `NetApiBufferFree` from NETUTILS library
- Uses Apollo's API resolution framework for dynamic loading

#### 2. Target Computer Determination
```csharp
string serverName = _data.Parameters.Trim();
if (string.IsNullOrEmpty(serverName))
{
    serverName = Environment.GetEnvironmentVariable("COMPUTERNAME");
}
```
- Uses provided computer name parameter
- Defaults to local computer name if no parameter specified
- Supports both hostname and FQDN formats

#### 3. Local Group Enumeration
```csharp
res = _pNetLocalGroupEnum(serverName, level, out buffer, MAX_PREFERRED_LENGTH,
    out read, out total, ref handle);
```
- Calls `NetLocalGroupEnum` with level 1 for group information
- Uses `MAX_PREFERRED_LENGTH` (-1) for optimal buffer allocation
- Returns buffer containing group structures and counts

#### 4. Structure Marshaling and Processing
```csharp
IntPtr ptr = buffer;
for (int i = 0; i < read; i++)
{
    LocalGroupUsersInfo group = (LocalGroupUsersInfo) Marshal.PtrToStructure(ptr, typeof(LocalGroupUsersInfo));
    NetLocalGroup result = new NetLocalGroup();
    result.ComputerName = serverName;
    result.GroupName = Marshal.PtrToStringUni(@group.name);
    result.Comment = Marshal.PtrToStringUni(@group.comment);
    results.Add(result);
    ptr = ptr + Marshal.SizeOf(typeof(LocalGroupUsersInfo));
}
```
- Iterates through buffer entries using pointer arithmetic
- Marshals each structure from unmanaged memory
- Converts Unicode string pointers to managed strings
- Advances pointer by structure size for next entry

#### 5. Memory Management
```csharp
finally
{
    if (buffer != IntPtr.Zero)
    {
        _pNetApiBufferFree(buffer);
    }
}
```
- Ensures buffer cleanup using `NetApiBufferFree`
- Prevents memory leaks from unmanaged allocations
- Uses finally block for guaranteed cleanup

### Data Structures

#### LocalGroupUsersInfo (Unmanaged)
```csharp
[StructLayout(LayoutKind.Sequential)]
public struct LocalGroupUsersInfo
{
    public IntPtr name;     // Pointer to group name string
    public IntPtr comment;  // Pointer to group comment string
}
```

#### NetLocalGroup (Managed)
```csharp
struct NetLocalGroup
{
    public string ComputerName;  // Target computer name
    public string GroupName;     // Local group name
    public string Comment;       // Group description
    public string SID;          // Group security identifier
}
```

### Win32 API Integration

#### NetLocalGroupEnum Function
```csharp
private delegate int NetLocalGroupEnum(
    [MarshalAs(UnmanagedType.LPWStr)] string servername,
    int dwLevel,
    out IntPtr lpBuffer,
    int dwMaxLen,
    out int dwEntriesRead,
    out int dwTotalEntries,
    ref IntPtr lpResume);
```
- **servername**: Target computer name (null for local)
- **dwLevel**: Information level (1 for basic group info)
- **lpBuffer**: Receives pointer to allocated buffer
- **dwMaxLen**: Preferred maximum buffer length (-1 for optimal)
- **dwEntriesRead**: Number of entries returned
- **dwTotalEntries**: Total entries available
- **lpResume**: Resume handle for continuation

### Browser Interface Integration
The JavaScript processes the JSON response into an interactive table with:
- **Members Button**: Launches `net_localgroup_member` command for each group
- **Copy Icon**: Allows copying group SIDs
- **Sortable Columns**: Name, comment, and SID columns
- **Group Details**: Computer name, group name, comment, and SID

### Error Handling
```csharp
if (res != 0)
{
    resp = CreateTaskResponse($"Error enumuerating local groups: {res}", true, "error");
}
```
- Checks API return code for errors
- Common error codes:
  - **5**: Access denied
  - **53**: Network path not found
  - **1115**: No more entries available

## APIs Used
| API | Purpose | DLL |
|-----|---------|-----|
| `NetLocalGroupEnum` | Enumerate local groups | samcli.dll |
| `NetApiBufferFree` | Free allocated buffer | netutils.dll |
| `Marshal.PtrToStructure` | Convert unmanaged to managed | mscorlib.dll |
| `Marshal.PtrToStringUni` | Convert Unicode pointer to string | mscorlib.dll |

## MITRE ATT&CK Mapping
- **T1590** - Gather Victim Network Information
- **T1069** - Permission Groups Discovery
  - **T1069.001** - Local Groups

## Security Considerations
- **Information Disclosure**: Reveals local security group structure
- **Privilege Enumeration**: Shows administrative and privileged groups
- **Attack Planning**: Enables targeting of specific privilege groups
- **Detection Vectors**: Local group enumeration may be monitored

## Limitations
1. Requires network connectivity for remote computers
2. May need administrative privileges for some remote systems
3. Limited to local groups only (not domain groups)
4. Does not show group membership details
5. Subject to Windows security policies and access controls

## Error Conditions
- **Access Denied**: Insufficient privileges to enumerate groups
- **Network Path Not Found**: Target computer unreachable
- **Invalid Computer Name**: Specified computer doesn't exist
- **RPC Server Unavailable**: Remote procedure call failures
- **Buffer Allocation**: Memory allocation failures