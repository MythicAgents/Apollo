+++
title = "net_localgroup_member"
chapter = false
weight = 103
hidden = false
+++

## Summary
Enumerates members of a specified local group using `NetLocalGroupGetMembers` Win32 API. Retrieves member names, SIDs, and distinguishes between user and group members.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
- **computer** (Optional String) - Target computer name (defaults to localhost)
- **group** (String) - Local group name to enumerate members

## Usage
```
net_localgroup_member Administrators
net_localgroup_member client01.lab.local Administrators
```

**Raw Output:**
```json
[
  {
    "computer_name": "CLIENT01",
    "group_name": "Administrators",
    "member_name": "DOMAIN\\alice",
    "sid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
    "is_group": false
  }
]
```

**Formatted Output:**
![net_localgroup_member command](../images/net_localgroup_member.png)

## Detailed Summary

### Agent Execution Flow

#### 1. API Function Resolution
```csharp
public net_localgroup_member(IAgent agent, ApolloInterop.Structs.MythicStructs.MythicTask data) : base(agent, data)
{
    _pNetLocalGroupGetMembers = _agent.GetApi().GetLibraryFunction<NetLocalGroupGetMembers>(Library.SAMCLI, "NetLocalGroupGetMembers");
    _pConvertSidToStringSid = _agent.GetApi().GetLibraryFunction<ConvertSidToStringSid>(Library.ADVAPI32, "ConvertSidToStringSidA");
    _pNetApiBufferFree = _agent.GetApi().GetLibraryFunction<NetApiBufferFree>(Library.NETUTILS, "NetApiBufferFree");
}
```
- Resolves `NetLocalGroupGetMembers` from SAMCLI library
- Resolves `ConvertSidToStringSid` from ADVAPI32 library
- Resolves `NetApiBufferFree` from NETUTILS library

#### 2. Parameter Processing
```csharp
[DataContract]
internal struct NetLocalGroupMemberParameters
{
    [DataMember(Name = "computer")]
    public string Computer;
    [DataMember(Name = "group")]
    public string Group;
}

NetLocalGroupMemberParameters args = _jsonSerializer.Deserialize<NetLocalGroupMemberParameters>(_data.Parameters);
if (string.IsNullOrEmpty(args.Computer))
{
    args.Computer = Environment.GetEnvironmentVariable("COMPUTERNAME");
}
```
- Deserializes computer and group parameters
- Defaults to local computer name if not specified

#### 3. Group Member Enumeration
```csharp
int val = _pNetLocalGroupGetMembers(args.Computer, args.Group, 2, out IntPtr bufPtr, -1, out entriesRead,
    out totalEntries, ref resumePtr);
```
- Calls `NetLocalGroupGetMembers` with level 2 for detailed member information
- Uses preferred maximum length (-1) for optimal buffer allocation
- Returns buffer containing member structures and counts

#### 4. Member Structure Processing
```csharp
LocalGroupMembersInfo[] groupMembers = new LocalGroupMembersInfo[entriesRead];
IntPtr iter = bufPtr;
for (int i = 0; i < entriesRead; i++)
{
    groupMembers[i] = (LocalGroupMembersInfo) Marshal.PtrToStructure(iter, typeof(LocalGroupMembersInfo));
    iter = iter + Marshal.SizeOf(typeof(LocalGroupMembersInfo));
}
```
- Creates array to hold member structures
- Iterates through buffer using pointer arithmetic
- Marshals each structure from unmanaged memory

#### 5. SID Conversion and Member Processing
```csharp
string sidString = "";
bool bRet = _pConvertSidToStringSid(groupMembers[i].lgrmi2_sid, out sidString);
if (!bRet)
    continue;

var result = new NetLocalGroupMember();
result.ComputerName = args.Computer;
result.GroupName = args.Group;
result.IsGroup = (groupMembers[i].lgrmi2_sidusage == SidNameUse.SidTypeGroup);
result.SID = sidString;
result.MemberName = Marshal.PtrToStringUni(groupMembers[i].lgrmi2_domainandname);
```
- Converts binary SID to string representation
- Determines if member is a group or user based on `SidNameUse`
- Extracts domain and name from Unicode string pointer
- Skips members where SID conversion fails

#### 6. Memory Management
```csharp
if (bufPtr != IntPtr.Zero)
{
    _pNetApiBufferFree(bufPtr);
}
```
- Frees allocated buffer using `NetApiBufferFree`
- Prevents memory leaks from unmanaged allocations

### Data Structures

#### LocalGroupMembersInfo (Unmanaged)
```csharp
[StructLayout(LayoutKind.Sequential)]
public struct LocalGroupMembersInfo
{
    public IntPtr lgrmi2_sid;           // Pointer to member SID
    public SidNameUse lgrmi2_sidusage;  // Type of SID (user/group)
    public IntPtr lgrmi2_domainandname; // Pointer to domain\name string
}
```

#### NetLocalGroupMember (Managed)
```csharp
struct NetLocalGroupMember
{
    public string ComputerName;  // Target computer name
    public string GroupName;     // Local group name
    public string MemberName;    // Member domain\name
    public string SID;          // String representation of SID
    public bool IsGroup;        // True if member is a group
}
```

#### SidNameUse Enumeration
```csharp
public enum SidNameUse
{
    SidTypeUser = 1,
    SidTypeGroup,
    SidTypeDomain,
    SidTypeAlias,
    SidTypeWellKnownGroup,
    SidTypeDeletedAccount,
    SidTypeInvalid,
    SidTypeUnknown,
    SidTypeComputer,
    SidTypeLabel,
    SidTypeLogonSession
}
```

### Win32 API Integration

#### NetLocalGroupGetMembers Function
```csharp
private delegate int NetLocalGroupGetMembers(
    [MarshalAs(UnmanagedType.LPWStr)] string servername,
    [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
    int level,
    out IntPtr bufptr,
    int prefmaxlen,
    out int entriesread,
    out int totalentries,
    ref IntPtr resume_handle);
```
- **servername**: Target computer name
- **localgroupname**: Local group to enumerate
- **level**: Information level (2 for detailed member info)
- **bufptr**: Receives buffer pointer
- **prefmaxlen**: Preferred maximum buffer length
- **entriesread**: Number of entries returned
- **totalentries**: Total entries available
- **resume_handle**: Continuation handle

### Browser Interface Integration
The JavaScript processes the JSON response into an interactive table with:
- **Group Type Column**: Distinguishes between "User" and "Group" members
- **Copy Icons**: Allows copying member names and SIDs
- **Dynamic Title**: Shows group name in table title
- **Member Details**: Computer, group, member name, SID, and type

## APIs Used
| API | Purpose | DLL |
|-----|---------|-----|
| `NetLocalGroupGetMembers` | Enumerate group members | samcli.dll |
| `ConvertSidToStringSid` | Convert SID to string | advapi32.dll |
| `NetApiBufferFree` | Free allocated buffer | netutils.dll |
| `Marshal.PtrToStructure` | Convert unmanaged to managed | mscorlib.dll |
| `Marshal.PtrToStringUni` | Convert Unicode pointer to string | mscorlib.dll |

## MITRE ATT&CK Mapping
- **T1590** - Gather Victim Network Information
- **T1069** - Permission Groups Discovery
  - **T1069.001** - Local Groups

## Security Considerations
- **Privilege Enumeration**: Reveals members of privileged groups
- **User Discovery**: Exposes user accounts with local privileges
- **Attack Planning**: Enables targeting of specific privileged users
- **Detection Vectors**: Group membership enumeration may be monitored

## Limitations
1. Requires access to target computer for remote enumeration
2. May need administrative privileges for some groups/systems
3. Only shows local group membership (not domain groups)
4. SID conversion failures skip affected members
5. Subject to Windows security policies and access controls

## Error Conditions
- **Access Denied**: Insufficient privileges to enumerate group
- **Group Not Found**: Specified group doesn't exist
- **Network Path Not Found**: Target computer unreachable
- **Invalid Parameter**: Malformed group or computer name
- **SID Conversion Failure**: Unable to convert binary SID to string