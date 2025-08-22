+++
title = "blockdlls"
chapter = false
weight = 103
hidden = false
+++

## Summary
The `blockdlls` function configures Apollo to prevent non-Microsoft signed DLLs from loading into sacrificial processes created by post-exploitation jobs. This security feature helps evade detection by preventing security products and other third-party DLLs from hooking into processes spawned by Apollo's post-exploitation commands such as `powerpick`, `execute_assembly`, `execute_pe`, and other commands that require sacrificial processes.

- **Needs Admin:** False
- **Version:** 3
- **Author:** @djhohnstein

### Arguments
- **block** (Boolean) - Enable or disable blocking of non-Microsoft signed DLLs (default: true)
  - **CLI Name:** EnableBlock
  - **Display Name:** Block Non-Microsoft DLLs

## Usage
### Example 1: Enable DLL Blocking (Default)
**Command:**
```
blockdlls
blockdlls -EnableBlock true
blockdlls true
```
**Output:**
```text
Task completed successfully
```

### Example 2: Disable DLL Blocking
**Command:**
```
blockdlls -EnableBlock false
blockdlls false
```
**Output:**
```text
Task completed successfully
```

### Example 3: Alternative Command Formats
**Command:**
```
blockdlls on
blockdlls off
```
**Output:**
```text
Task completed successfully
```

## Detailed Summary

The `blockdlls` function implements a configuration change that affects how Apollo creates sacrificial processes for post-exploitation commands. Based on the actual source code and verified information from Apollo's releases:

### 1. Parameter Processing and Validation

The function handles multiple input formats for operator convenience:

* **JSON Parameter Structure**: Uses `BlockDllsParameters` structure containing a single boolean `Value` field mapped from the `"block"` JSON member
* **Command Line Parsing**: The Python handler (`BlockDllsArguments`) processes various text inputs:
  - `"true"`, `"on"` → Enable DLL blocking (sets `block` parameter to `True`)
  - `"false"`, `"off"` → Disable DLL blocking (sets `block` parameter to `False`)
  - Default value when no parameter specified → Enable DLL blocking (default value is `True`)
* **Exception Handling**: Raises exceptions for invalid command line arguments or missing parameters

### 2. Core Implementation

The C# implementation is straightforward:

```csharp
public override void Start()
{
    BlockDllsParameters parameters = _jsonSerializer.Deserialize<BlockDllsParameters>(_data.Parameters);
    _agent.GetProcessManager().BlockDLLs(parameters.Value);
    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("", true));
}
```

**Key Implementation Details**:
* **Parameter Deserialization**: Uses the agent's JSON serializer to convert task parameters
* **ProcessManager Integration**: Calls `BlockDLLs(bool)` method on the agent's ProcessManager instance
* **Silent Success**: Returns empty response body with success status (`CreateTaskResponse("", true)`)
* **No Error Handling**: No explicit error handling around the ProcessManager call

### 3. ProcessManager Implementation

The actual ProcessManager implementation shows how DLL blocking is managed:

```csharp
public class ProcessManager : IProcessManager
{
    private bool _blockDlls = false;
    // ... other fields

    public bool BlockDLLs(bool status)
    {
        _blockDlls = status;
        return true;
    }

    public ApplicationStartupInfo GetStartupInfo(bool x64 = true)
    {
        ApplicationStartupInfo results = new ApplicationStartupInfo();
        results.Application = x64 ? _applicationx64 : _applicationx86;
        results.Arguments = x64 ? _argumentsx64 : _argumentsx86;
        results.ParentProcessId = _ppid;
        results.BlockDLLs = _blockDlls;
        return results;
    }
}
```

**ProcessManager Integration Details**:
* **Private Field Storage**: The `_blockDlls` boolean field stores the current DLL blocking state (defaults to `false`)
* **Simple State Management**: `BlockDLLs(bool status)` simply updates the `_blockDlls` field and returns `true`
* **Startup Info Integration**: `GetStartupInfo()` includes the `BlockDLLs` setting in the `ApplicationStartupInfo` structure
* **Architecture Awareness**: The startup info considers both x64 and x86 process creation

### 4. Process Creation Integration

The ProcessManager includes additional fields that work together with DLL blocking:

```csharp
private bool _blockDlls = false;
private int _ppid = System.Diagnostics.Process.GetCurrentProcess().Id;
private string _applicationx64 = @"C:\Windows\System32\rundll32.exe";
private string _applicationx86 = @"C:\Windows\SysWOW64\rundll32.exe";
private string _argumentsx64 = null;
private string _argumentsx86 = null;
```

**Default Configuration**:
* **DLL Blocking**: Disabled by default (`_blockDlls = false`)
* **Parent Process ID**: Set to current Apollo process ID
* **x64 Sacrificial Process**: `C:\Windows\System32\rundll32.exe` (default)
* **x86 Sacrificial Process**: `C:\Windows\SysWOW64\rundll32.exe` (default)
* **Process Arguments**: `null` by default for both architectures

### 5. Sacrificial Process Creation

The ProcessManager creates new processes through the `NewProcess` method:

```csharp
public ApolloInterop.Classes.Core.Process NewProcess(string lpApplication, string lpArguments, bool startSuspended = false)
{
    return new SacrificialProcess(
        _agent,
        lpApplication,
        lpArguments,
        startSuspended);
}
```

**Process Creation Details**:
* **SacrificialProcess Class**: Uses a dedicated `SacrificialProcess` class for process creation
* **Startup Configuration**: The `ApplicationStartupInfo` structure includes the DLL blocking setting
* **Agent Context**: Passes the agent instance to the new process for integration
* **Suspension Support**: Can create processes in suspended state for injection scenarios

### 6. Integration with SpawnTo Configuration

The ProcessManager integrates DLL blocking with sacrificial process configuration:

```csharp
public bool SetSpawnTo(string lpApplication, string lpCommandLine = null, bool x64 = true)
{
    if (x64)
    {
        _applicationx64 = lpApplication;
        _argumentsx64 = lpCommandLine;
    }
    else
    {
        _applicationx86 = lpApplication;
        _argumentsx86 = lpCommandLine;
    }
    return true;
}
```

**SpawnTo Integration**:
* **Architecture-Specific**: Maintains separate application paths for x64 and x86 processes
* **Command Line Arguments**: Supports configurable arguments for each architecture
* **Combined Configuration**: The `GetStartupInfo()` method combines the spawnto configuration with DLL blocking settings
* **Always Successful**: Returns `true` indicating successful configuration update

### 7. PPID Integration

The ProcessManager also manages parent process ID spoofing alongside DLL blocking:

```csharp
public bool SetPPID(int pid)
{
    bool bRet = false;
    try
    {
        var curProc = System.Diagnostics.Process.GetCurrentProcess();
        var proc = System.Diagnostics.Process.GetProcessById(pid);
        if (proc.SessionId != curProc.SessionId)
            bRet = false;
        else
        {
            bRet = true;
            _ppid = pid;
        }
    }
    catch { }
    return bRet;
}
```

**PPID Configuration Details**:
* **Session Validation**: Ensures target parent process is in the same session as the current Apollo process
* **Process Validation**: Verifies the target PID exists using `Process.GetProcessById()`
* **Error Handling**: Uses try-catch with silent failure for invalid PIDs
* **Combined with DLL Blocking**: The PPID setting is included in `ApplicationStartupInfo` along with DLL blocking

### 8. ApplicationStartupInfo Structure

The ProcessManager populates the `ApplicationStartupInfo` structure with all configuration:

```csharp
public ApplicationStartupInfo GetStartupInfo(bool x64 = true)
{
    ApplicationStartupInfo results = new ApplicationStartupInfo();
    results.Application = x64 ? _applicationx64 : _applicationx86;
    results.Arguments = x64 ? _argumentsx64 : _argumentsx86;
    results.ParentProcessId = _ppid;
    results.BlockDLLs = _blockDlls;
    return results;
}
```

**Startup Info Contents**:
* **Application Path**: Architecture-specific executable path
* **Arguments**: Architecture-specific command line arguments
* **Parent Process ID**: Configured PPID for process creation
* **DLL Blocking**: Current DLL blocking state
* **Architecture Selection**: Chooses between x64 and x86 configurations based on parameter

### 9. Command Parsing Implementation Details

The Python argument parser implements flexible input handling:

```python
async def parse_arguments(self):
    if len(self.command_line) == 0:
        raise Exception("No action given.")
    if self.command_line[0] == "{":
        self.load_args_from_json_string(self.command_line)
    else:
        cmd = self.command_line.strip().lower()
        if cmd == "true" or cmd == "on":
            self.add_arg("block", True, ParameterType.Boolean)
        elif cmd == "false" or cmd == "off":
            self.add_arg("block", False, ParameterType.Boolean)
        else:
            raise Exception("Invalid command line arguments for blockdlls.")
```

**Parsing Features**:
* **JSON Support**: Accepts JSON-formatted parameters
* **Case Insensitive**: Converts input to lowercase before processing
* **Multiple Formats**: Supports "true/false" and "on/off" syntax
* **Error Handling**: Raises exceptions for invalid inputs or empty commands
* **Parameter Addition**: Uses `add_arg()` to set the boolean parameter

### 10. Display and Response Handling

The command response handling is implemented in both C# and Python components:

**C# Response**:
```csharp
_agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("", true));
```

**Python Display**:
```python
async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
    response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
    block = taskData.args.get_arg("block")
    if block:
        response.DisplayParams = "true"
    else:
        response.DisplayParams = "false"
    return response
```

**Response Characteristics**:
* **Silent Execution**: C# component returns empty response body
* **Display Parameters**: Python component sets display parameters to "true" or "false"
* **Success Status**: Both components indicate successful task completion
* **Guaranteed Success**: ProcessManager.BlockDLLs() always returns `true`, ensuring successful task completion

### 11. Configuration Scope and Persistence

Based on the ProcessManager implementation:

* **Private Field Storage**: The `_blockDlls` field is stored as a private instance variable in the ProcessManager
* **Agent Lifetime**: Configuration persists for the current agent session since it's stored in memory
* **Global Impact**: Affects all subsequent calls to `GetStartupInfo()` which provides configuration for process creation
* **Override Capability**: Can be changed by issuing another `blockdlls` command (calls `BlockDLLs()` again)
* **No Persistence**: Does not persist across agent restarts since it's stored in memory
* **Default State**: Defaults to `false` (DLL blocking disabled) when ProcessManager is initialized

### 12. Integration with Related Commands

The ProcessManager integrates `blockdlls` with other process management commands:

* **spawnto_x86/spawnto_x64**: Uses `SetSpawnTo()` to configure sacrificial process executables
* **ppid**: Uses `SetPPID()` to configure parent process ID spoofing
* **Combined Configuration**: All settings are combined in `ApplicationStartupInfo` for process creation
* **No Conflicts**: All settings work together without conflicts since they're stored in separate fields

### 13. Operational Considerations

**Implementation Details** (from actual source code):
* **Simple State Management**: The implementation is straightforward - just setting a boolean flag
* **Always Successful**: The `BlockDLLs()` method always returns `true`, indicating no validation or error checking
* **Memory-Based**: All configuration is stored in memory within the ProcessManager instance
* **Architecture Aware**: The system maintains separate configurations for x64 and x86 processes

**Default Behavior**:
* **DLL Blocking**: Disabled by default (`_blockDlls = false`)
* **Sacrificial Processes**: Uses `rundll32.exe` from System32 (x64) and SysWOW64 (x86) by default
* **Parent Process**: Uses current Apollo process as parent by default
* **No Arguments**: Process arguments are `null` by default

**Integration Points**:
* The `ApplicationStartupInfo` structure is the key integration point where all process creation settings are combined
* The `SacrificialProcess` class receives these settings and implements the actual process creation
* The ProcessManager acts as a centralized configuration store for all process creation parameters

## MITRE ATT&CK Mapping
- **T1055** - Process Injection
- **T1562** - Impair Defenses
  - **T1562.001** - Disable or Modify Tools

## APIs Used and Their Purposes
| API | Purpose | DLL | Documentation |
|------|---------|-----|--------------|
| `IAgent.GetProcessManager().BlockDLLs(bool)` | Configures DLL blocking for sacrificial processes | Apollo Agent | Internal Apollo API |
| `JsonSerializer.Deserialize<BlockDllsParameters>()` | Deserializes JSON task parameters | Apollo Agent | Internal Apollo JSON serialization |
| `IAgent.GetTaskManager().AddTaskResponseToQueue()` | Queues task response for return to Mythic | Apollo Agent | Internal Apollo API |

## Security Considerations

### Operational Security Benefits
1. **Detection Evasion**: Prevents security products from loading monitoring DLLs into sacrificial processes
2. **Clean Execution Environment**: Sacrificial processes run without third-party modifications
3. **Stealth Enhancement**: Reduces attack surface visible to security monitoring tools

### Potential Operational Impacts
1. **Tool Compatibility**: Some tools may fail if they require non-Microsoft DLLs
2. **Functionality Loss**: Advanced features of some tools may be disabled
3. **Debug Difficulty**: Troubleshooting becomes more difficult when expected DLLs are blocked

### Configuration Management
1. **Global Setting**: Affects all sacrificial processes created after the command is issued
2. **Session Scope**: Setting persists only for the current agent session
3. **Override Capability**: Can be changed at any time during agent execution

## Limitations

1. **Microsoft-Only Restriction**: Only Microsoft-signed DLLs are allowed in sacrificial processes
2. **Global Application**: Cannot selectively apply to specific commands
3. **Session Persistence**: Configuration does not persist across agent restarts
4. **No Validation**: No confirmation that the setting was successfully applied
5. **Implementation Dependency**: Effectiveness depends on the underlying ProcessManager implementation
6. **Compatibility Issues**: Apollo's releases indicate the feature required multiple hotfixes

## Troubleshooting

### Common Issues and Solutions

| Issue | Possible Causes | Solutions |
|-------|----------------|-----------|
| Tool fails after enabling DLL blocking | Tool requires non-Microsoft DLLs | Disable DLL blocking with `blockdlls false` |
| No visible change in behavior | Setting may be already configured | Check current setting with other process management commands |
| Command execution error | Invalid command line syntax | Use supported formats: true/false or on/off |

### Debugging Steps
1. **Verify Syntax**: Ensure command uses supported parameter formats
2. **Test Impact**: Execute a sacrificial process command to test the setting's effect
3. **Toggle Setting**: Try both enabling and disabling to verify functionality
4. **Check Compatibility**: Test specific tools that may require third-party DLLs

## References

- [Apollo Agent Source Code](https://github.com/MythicAgents/Apollo)
- [Apollo Release Notes](https://github.com/MythicAgents/Apollo/releases)
- [Process Injection Techniques](https://attack.mitre.org/techniques/T1055/)
- [Windows Process Creation](https://docs.microsoft.com/en-us/windows/win32/procthread/creating-processes)