+++
title = "spawnto_x64"
chapter = false
weight = 103
hidden = false
+++

## Summary
Configures the default 64-bit executable and arguments used for post-exploitation jobs that require process creation. Sets the application path and optional arguments in Apollo's process manager for use by commands like `spawn` and other process injection operations.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
- **application** (String, Required) - Full path to 64-bit executable (default: C:\Windows\System32\rundll32.exe)
- **arguments** (String, Optional) - Command line arguments to pass to the executable

## Usage
```
spawnto_x64 -Application C:\Windows\System32\notepad.exe
spawnto_x64 -Application C:\Windows\System32\rundll32.exe -Arguments "shell32.dll,Control_RunDLL"
spawnto_x64 C:\Windows\System32\calc.exe
```

**Output:**
```
x64 Startup Information set to: C:\Windows\System32\notepad.exe 
```

## Detailed Summary

### Agent Execution Flow

#### 1. Parameter Processing
```csharp
[DataContract]
internal struct SpawnToArgsx64
{
    [DataMember(Name = "application")] public string Application;
    [DataMember(Name = "arguments")] public string Arguments;
}

SpawnToArgsx64 parameters = _jsonSerializer.Deserialize<SpawnToArgsx64>(_data.Parameters);
```
- Deserializes application path and arguments from JSON
- Supports both JSON and command-line parameter formats
- Application parameter is required, arguments are optional

#### 2. Command Line Parsing (Python)
```python
def split_commandline(self):
    inQuotes = False
    curCommand = ""
    cmds = []
    for x in range(len(self.command_line)):
        c = self.command_line[x]
        if c == '"' or c == "'":
            inQuotes = not inQuotes
        if (not inQuotes and c == ' '):
            cmds.append(curCommand)
            curCommand = ""
        else:
            curCommand += c
    
    if curCommand != "":
        cmds.append(curCommand)
    
    return cmds
```
- Handles quoted arguments properly
- Splits command line respecting quote boundaries
- Removes surrounding quotes from arguments

#### 3. Parameter Validation and Setup
```python
async def parse_arguments(self):
    if len(self.command_line) == 0:
        raise Exception("spawnto_x64 requires a path to an executable")
    
    if self.command_line[0] == "{":
        self.load_args_from_json_string(self.command_line)
    else:
        parts = self.split_commandline()
        self.add_arg("application", parts[0])
        firstIndex = self.command_line.index(parts[0])
        cmdline = self.command_line[firstIndex+len(parts[0]):].strip()
        if cmdline[0] in ['"', "'"]:
            cmdline = cmdline[1:].strip()
        self.add_arg("arguments", cmdline)
```
- Validates executable path is provided
- Supports both JSON and space-separated formats
- Extracts application path and remaining arguments

#### 4. Process Manager Configuration
```csharp
if (_agent.GetProcessManager().SetSpawnTo(parameters.Application, parameters.Arguments, true))
{
    var sacParams = _agent.GetProcessManager().GetStartupInfo();
    resp = CreateTaskResponse(
        $"x64 Startup Information set to: {sacParams.Application} {sacParams.Arguments}",
        true);
}
else
{
    resp = CreateTaskResponse("Failed to set startup information.", true, "error");
}
```
- Calls `SetSpawnTo` on process manager with application, arguments, and x64 flag (true)
- Retrieves updated startup info to confirm configuration
- Provides success confirmation with configured values
- Handles configuration failures with error message

### Process Manager Integration

#### SetSpawnTo Method
```csharp
// Called with parameters:
// - parameters.Application: Full path to executable
// - parameters.Arguments: Command line arguments
// - true: Flag indicating x64 architecture
_agent.GetProcessManager().SetSpawnTo(parameters.Application, parameters.Arguments, true);
```
- Sets 64-bit specific spawn configuration
- Third parameter (true) indicates x64 architecture
- Stores configuration for use by other commands

#### GetStartupInfo Method
```csharp
var sacParams = _agent.GetProcessManager().GetStartupInfo();
// Returns configured application and arguments
```
- Retrieves current startup configuration
- Used to confirm successful configuration
- Returns structure with Application and Arguments properties

### Default Configuration

#### Default Values
```python
CommandParameter(
    name="application",
    type=ParameterType.String, 
    default_value="C:\\Windows\\System32\\rundll32.exe"
),
CommandParameter(
    name="arguments", 
    type=ParameterType.String, 
    default_value="", 
    required=False
)
```
- Default 64-bit executable: `C:\Windows\System32\rundll32.exe`
- Default arguments: empty string
- Arguments are optional parameter

#### Display Parameters
```python
response.DisplayParams = "-Application {}".format(taskData.args.get_arg("application"))
if args:
    response.DisplayParams += " -Arguments {}".format(args)
```
- Shows configured application path
- Includes arguments in display if provided
- Used for task display in Mythic interface

### Error Handling

#### Configuration Failure
```csharp
if (_agent.GetProcessManager().SetSpawnTo(parameters.Application, parameters.Arguments, true))
{
    // Success path
}
else
{
    resp = CreateTaskResponse("Failed to set startup information.", true, "error");
}
```
- Single error condition: SetSpawnTo method returns false
- Generic error message for configuration failures
- No specific error details provided

#### Parameter Validation
```python
if len(self.command_line) == 0:
    raise Exception("spawnto_x64 requires a path to an executable")
```
- Validates that executable path is provided
- Raises exception if no command line provided
- No validation of executable existence or accessibility

### Integration with Other Commands

#### Commands That Use Spawnto Configuration
Based on the code, commands that call `_agent.GetProcessManager().GetStartupInfo()` will use this configuration:
- `spawn` command uses startup info for process creation
- Other process injection commands may use this configuration

#### Architecture Relationship
- `spawnto_x64` sets 64-bit configuration (true flag)
- Likely counterpart to `spawnto_x86` for 32-bit configuration
- Commands determine which configuration to use based on payload architecture

### Data Structures

#### SpawnToArgsx64 Structure
```csharp
[DataContract]
internal struct SpawnToArgsx64
{
    [DataMember(Name = "application")] public string Application;
    [DataMember(Name = "arguments")] public string Arguments;
}
```

#### Command Parameters
```python
self.args = [
    CommandParameter(
        name="application",
        cli_name="Application", 
        display_name="Path to Application", 
        type=ParameterType.String, 
        default_value="C:\\Windows\\System32\\rundll32.exe"
    ),
    CommandParameter(
        name="arguments", 
        cli_name="Arguments", 
        display_name="Arguments", 
        type=ParameterType.String, 
        default_value="", 
        required=False
    )
]
```

## APIs Used
| API | Purpose | Integration |
|-----|---------|-------------|
| `SetSpawnTo()` | Configure spawn executable | Apollo ProcessManager |
| `GetStartupInfo()` | Retrieve startup configuration | Apollo ProcessManager |
| `split_commandline()` | Parse command line arguments | Internal Method |
| `load_args_from_json_string()` | Parse JSON parameters | TaskArguments |

## MITRE ATT&CK Mapping
- **T1055** - Process Injection

## Security Considerations
- **Process Configuration**: Sets default executable for process creation operations
- **Persistence**: Configuration persists for agent session duration
- **Process Selection**: Choice of executable affects stealth of subsequent operations
- **Command Line Arguments**: Arguments may be visible in process listings

## Limitations
1. **No Path Validation**: Does not verify executable exists or is accessible
2. **Session Scope**: Configuration limited to current agent session
3. **Architecture Specific**: Only configures 64-bit executable path
4. **No Error Details**: Limited error information on configuration failure
5. **Static Configuration**: Cannot dynamically change based on target requirements

## Error Conditions
- **No Executable Path**: Command line is empty
- **Configuration Failed**: SetSpawnTo method returns false
- **Invalid JSON**: Malformed JSON parameters (if using JSON format)

## Best Practices
1. **Executable Selection**: Choose legitimate, commonly present executables
2. **Path Verification**: Verify executable exists before configuration
3. **Argument Consideration**: Be aware arguments may be visible in process lists
4. **Architecture Matching**: Ensure executable matches intended architecture (64-bit)
5. **Default Awareness**: Understand default (rundll32.exe) implications