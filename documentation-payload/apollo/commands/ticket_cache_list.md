+++
title = "ticket_cache_list"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: WindowsAPIInvoke
{{% /notice %}}

## Summary
Lists all Kerberos tickets in the current logon session using LSA APIs. When executed from an elevated context, can enumerate tickets from all logon sessions or target a specific session by LUID. Provides filtering options for system tickets.

- **Needs Admin:** False (elevated context enables cross-session enumeration)
- **Version:** 2
- **Author:** @drago-qcc

### Arguments
- **luid** (String, Optional) - Target LUID to filter tickets (requires elevation)
- **getSystemTickets** (Boolean, Optional) - Include system context tickets (default: true)

## Usage
```
ticket_cache_list {}
ticket_cache_list {"luid": "0x12345678"}
ticket_cache_list {"getSystemTickets": false}
ticket_cache_list {"luid": "0x12345678", "getSystemTickets": true}
```

**Output:**
```
Interactive table showing:
- Client Name
- Server Name  
- Start Time
- End Time
- Encryption Type
- Ticket Flags
- LUID
```

## Detailed Summary

### Agent Execution Flow

#### 1. Parameter Processing and Validation
```python
async def parse_arguments(self):
    if self.command_line[0] != "{":
        raise Exception("Require JSON blob, but got raw command line.")
    self.load_args_from_json_string(self.command_line)
```
- Requires JSON parameter format only
- LUID parameter is optional for targeting specific sessions
- getSystemTickets parameter controls system ticket filtering

#### 2. Display Parameter Configuration
```python
async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    getSystemTickets = taskData.args.get_arg("getSystemTickets")
    luid = taskData.args.get_arg("luid")
    response.DisplayParams += f" -getSystemTickets {getSystemTickets}"
    if luid != "":
        response.DisplayParams += f" -luid {luid}"
```
- Shows getSystemTickets setting in display parameters
- Includes LUID in display when specified
- Provides clear operation summary

#### 3. Ticket Enumeration Process (C#)
```csharp
// From KerberosHelpers.cs - TriageTickets method
internal static IEnumerable<KerberosTicket> TriageTickets(bool getSystemTickets = false, string targetLuid = "")
{
    List<KerberosTicket> allTickets = [];
    (HANDLE lsaHandle, uint authPackage, IEnumerable<LUID> logonSessions, string error) = InitKerberosConnectionAndSessionInfo();
    
    if(lsaHandle.IsNull || authPackage == 0 || !logonSessions.Any() || error != "")
    {
        return allTickets;
    }
    
    foreach (var logonSession in logonSessions)
    {
        if(!string.IsNullOrWhiteSpace(targetLuid) && logonSession.ToString() != targetLuid)
        {
            continue;
        }
        
        var sessionData = GetLogonSessionData(new(logonSession));
        if (getSystemTickets is false && sessionData.Session is 0)
        {
            continue;
        }
        
        var tickets = GetTicketCache(lsaHandle, authPackage, logonSession);
        allTickets.AddRange(tickets);
    }
}
```
- Enumerates all logon sessions on the system
- Filters by target LUID when specified
- Applies system ticket filtering based on session ID
- Aggregates tickets from all matching sessions

#### 4. LSA Connection and Session Enumeration
```csharp
// From KerberosHelpers.cs
private static IEnumerable<LUID> GetLogonSessions()
{
    List<LUID> logonIds = [];
    WindowsAPI.LsaEnumerateLogonSessionsDelegate(out uint logonCount, out HANDLE logonIdHandle);
    createdArtifacts.Add(Artifact.WindowsAPIInvoke("LsaEnumerateLogonSessions"));
    
    var logonWorkingHandle = logonIdHandle;
    for (var i = 0; i < logonCount; i++)
    {
        var logonId = logonWorkingHandle.CastTo<LUID>();
        if (logonId.IsNull || logonIds.Contains(logonId))
        {
            continue;
        }
        logonIds.Add(logonId);
        logonWorkingHandle = logonWorkingHandle.Increment();
    }
    WindowsAPI.LsaFreeReturnBufferDelegate(logonIdHandle);
    return logonIds;
}
```
- Uses `LsaEnumerateLogonSessions` to get all session LUIDs
- Iterates through session array with proper pointer arithmetic
- Handles duplicate LUID detection and filtering
- Properly frees LSA memory resources

#### 5. Session Data Retrieval
```csharp
private static LogonSessionData GetLogonSessionData(HANDLE<LUID> luidHandle)
{
    WindowsAPI.LsaGetLogonSessionDataDelegate(luidHandle, out logonSessionDataHandle);
    createdArtifacts.Add(Artifact.WindowsAPIInvoke("LsaGetLogonSessionData"));
    
    var seclogonSessionData = logonSessionDataHandle.CastTo<SECURITY_LOGON_SESSION_DATA>();
    LogonSessionData sessionData = new()
    {
        LogonId = seclogonSessionData.LogonId,
        Username = seclogonSessionData.UserName.ToString(),
        LogonDomain = seclogonSessionData.LogonDomain.ToString(),
        AuthenticationPackage = seclogonSessionData.AuthenticationPackage.ToString(),
        LogonType = (Win32.LogonType)seclogonSessionData.LogonType,
        Session = (int)seclogonSessionData.Session,
        Sid = seclogonSessionData.Sid.IsNull ? null : new SecurityIdentifier(seclogonSessionData.Sid),
        LogonTime = DateTime.FromFileTime(seclogonSessionData.LogonTime),
        LogonServer = seclogonSessionData.LogonServer.ToString(),
        DnsDomainName = seclogonSessionData.DnsDomainName.ToString(),
        Upn = seclogonSessionData.Upn.ToString()
    };
    return sessionData;
}
```
- Retrieves detailed session information for each LUID
- Extracts username, domain, session ID, and other metadata
- Converts Windows structures to managed objects
- Handles null pointer checks for optional fields

#### 6. Ticket Cache Querying
```csharp
private static IEnumerable<KerberosTicket> GetTicketCache(HANDLE lsaHandle, uint authPackage, LUID logonId)
{
    LUID UsedlogonId = logonId;
    if (Agent.GetIdentityManager().GetIntegrityLevel() <= IntegrityLevel.MediumIntegrity)
    {
        UsedlogonId = new LUID();
    }

    KERB_QUERY_TKT_CACHE_REQUEST request = new()
    {
        MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheExMessage,
        LogonId = UsedlogonId
    };

    var status = WindowsAPI.LsaCallAuthenticationPackageDelegate(lsaHandle, authPackage, requestHandle, Marshal.SizeOf(request), out HANDLE returnBuffer, out uint returnLength, out NTSTATUS returnStatus);
    createdArtifacts.Add(Artifact.WindowsAPIInvoke("LsaCallAuthenticationPackage"));

    var response = returnBuffer.CastTo<KERB_QUERY_TKT_CACHE_RESPONSE>();
    HANDLE<KERB_TICKET_CACHE_INFO_EX> ticketHandle = (HANDLE<KERB_TICKET_CACHE_INFO_EX>)returnBuffer.Increment();
    
    for (var i = 0; i < response.CountOfTickets; i++)
    {
        var lpTicket = ticketHandle.GetValue();
        var foundTicket = new KerberosTicket
        {
            Luid = logonId,
            ClientName = lpTicket.ClientName.ToString(),
            ClientRealm = lpTicket.ClientRealm.ToString(),
            ServerName = lpTicket.ServerName.ToString(),
            ServerRealm = lpTicket.ServerRealm.ToString(),
            StartTime = DateTime.FromFileTime(lpTicket.StartTime),
            EndTime = DateTime.FromFileTime(lpTicket.EndTime),
            RenewTime = DateTime.FromFileTime(lpTicket.RenewTime),
            EncryptionType = (KerbEncType)lpTicket.EncryptionType,
            TicketFlags = (KerbTicketFlags)lpTicket.TicketFlags
        };
        tickets.Add(foundTicket);
        ticketHandle = ticketHandle.IncrementBy(Marshal.SizeOf<KERB_TICKET_CACHE_INFO_EX>());
    }
    WindowsAPI.LsaFreeReturnBufferDelegate(returnBuffer);
}
```
- Queries ticket cache for specific logon session
- Clears LUID for non-elevated contexts to use current session
- Processes ticket cache response structure
- Extracts detailed ticket information including timing and encryption

#### 7. System Ticket Filtering Logic
```csharp
var sessionData = GetLogonSessionData(new(logonSession));
if (getSystemTickets is false && sessionData.Session is 0)
{
    continue;
}
```
- Retrieves session data to check session ID
- Session ID 0 indicates system/service context
- Skips system tickets when getSystemTickets is false
- Allows filtering out service account tickets

### Filtering and LUID Handling

#### Target LUID Filtering
```csharp
if(!string.IsNullOrWhiteSpace(targetLuid) && logonSession.ToString() != targetLuid)
{
    continue;
}
```
- Compares session LUID with target LUID parameter
- Skips sessions that don't match target when specified
- Allows precise targeting of specific logon sessions

#### Integrity Level Considerations
```csharp
if (Agent.GetIdentityManager().GetIntegrityLevel() <= IntegrityLevel.MediumIntegrity)
{
    UsedlogonId = new LUID();
}
```
- Uses null LUID for non-elevated contexts
- Limits enumeration to current session when not elevated
- Prevents access to other users' sessions without elevation

### Browser Script Integration

#### UI Features
```python
supported_ui_features = ["apollo:ticket_cache_list"]
browser_script = BrowserScript(script_name="ticket_cache_list", author="@its_a_feature_", for_new_ui=True)
```
- Provides interactive table display for ticket information
- Enables sorting and filtering of ticket data
- Shows detailed ticket metadata in structured format

### Parameter Configuration

#### Default Values
```python
CommandParameter(
    name="getSystemTickets",
    type=ParameterType.Boolean,
    default_value=True,
    description="Set this to false to filter out tickets for the SYSTEM context"
),
CommandParameter(
    name="luid",
    type=ParameterType.String,
    default_value="",
    description="From an elevated context a LUID may be provided to target a specific session"
)
```
- getSystemTickets defaults to true (includes system tickets)
- LUID defaults to empty string (all accessible sessions)
- Optional parameters for flexible enumeration

### Integration with TicketManager

#### Interface Methods
```csharp
// From KerberosTicketManager.cs
public List<KerberosTicket> EnumerateTicketsInCache(bool getSystemTickets = false, string luid = "") => 
    KerberosHelpers.TriageTickets(getSystemTickets, luid).ToList();
```
- Provides clean interface to enumeration functionality
- Handles parameter passing to helper methods
- Returns list of KerberosTicket objects

### Error Handling

#### Connection Initialization Errors
```csharp
(HANDLE lsaHandle, uint authPackage, IEnumerable<LUID> logonSessions, string error) = InitKerberosConnectionAndSessionInfo();

if(lsaHandle.IsNull || authPackage == 0 || !logonSessions.Any() || error != "")
{
    return allTickets; // Return empty list
}
```
- Validates LSA connection establishment
- Checks authentication package lookup success
- Ensures logon sessions were enumerated
- Returns empty list on initialization failures

#### Resource Cleanup
```csharp
finally
{
    WindowsAPI.LsaDeregisterLogonProcessDelegate(lsaHandle);
    createdArtifacts.Add(Artifact.WindowsAPIInvoke("LsaDeregisterLogonProcess"));
}
```
- Ensures LSA connection cleanup
- Generates artifacts for cleanup operations
- Prevents resource leaks on errors

## APIs Used
| API | Purpose | DLL |
|-----|---------|-----|
| `LsaConnectUntrusted` | Connect to LSA | advapi32.dll |
| `LsaEnumerateLogonSessions` | Get all logon session LUIDs | advapi32.dll |
| `LsaGetLogonSessionData` | Get session metadata | advapi32.dll |
| `LsaLookupAuthenticationPackage` | Get Kerberos auth package | advapi32.dll |
| `LsaCallAuthenticationPackage` | Query ticket caches | advapi32.dll |
| `LsaFreeReturnBuffer` | Free LSA memory | advapi32.dll |
| `LsaDeregisterLogonProcess` | Close LSA connection | advapi32.dll |

## MITRE ATT&CK Mapping
- **T1550** - Use Alternate Authentication Material

## Security Considerations
- **Session Enumeration**: Enumerates all logon sessions on system when elevated
- **Ticket Exposure**: Reveals Kerberos ticket metadata for accessible sessions
- **Cross-Session Access**: Can view other users' tickets when elevated
- **System Ticket Access**: Can enumerate service account tickets
- **LSA Interaction**: Direct interaction with Local Security Authority

## Limitations
1. **JSON Format Only**: Requires JSON parameter format
2. **Elevation for Cross-Session**: Multi-session enumeration requires elevated context
3. **LSA Dependencies**: Requires functional LSA subsystem
4. **Session Access**: Limited to accessible logon sessions
5. **Metadata Only**: Shows ticket information but not encoded ticket data
6. **System Filtering**: System ticket filtering based on session ID only

## Error Conditions
- **Invalid JSON**: Malformed JSON parameters
- **LSA Connection Failed**: Cannot connect to Local Security Authority
- **Session Enumeration Failed**: Cannot enumerate logon sessions
- **Package Lookup Failed**: Kerberos authentication package not found
- **Ticket Query Failed**: Cannot query ticket cache for session
- **Access Denied**: Insufficient privileges for target sessions
- **Invalid LUID**: Specified LUID does not exist or is inaccessible

## Best Practices
1. **Parameter Awareness**: Understand filtering implications of getSystemTickets setting
2. **Session Targeting**: Use LUID parameter for focused enumeration when elevated
3. **Error Monitoring**: Check for enumeration failures and access issues
4. **Resource Management**: Monitor system impact of full session enumeration
5. **Context Understanding**: Be aware of elevation requirements for cross-session access