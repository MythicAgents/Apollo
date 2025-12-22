+++
title = "run"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Create
{{% /notice %}}

## Summary
Executes binaries with specified arguments using proper command-line parsing and PATH resolution. Captures output in real-time and manages process lifecycle with cancellation support.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
- **executable** (String) - Path or name of executable to run
- **arguments** (String, Optional) - Command-line arguments for the executable

## Usage
```
run ipconfig /all
run -Executable notepad -Arguments "C:\file.txt"
run calc.exe
```

**Output:**
```
Windows IP Configuration

   Host Name . . . . . . . . . . . . : WORKSTATION01
   Primary Dns Suffix  . . . . . . . : domain.local
   ...
```

## Detailed Summary

### Agent Execution Flow

#### 1. Parameter Processing
```csharp
[DataContract]
internal struct RunParameters
{
    [DataMember(Name = "executable")] public string Executable;
    [DataMember(Name = "arguments")] public string Arguments;
}

RunParameters parameters = _jsonSerializer.Deserialize<RunParameters>(_data.Parameters);
string mythiccmd = parameters.Executable;
if (!string.IsNullOrEmpty(parameters.Arguments))
{
    mythiccmd += " " + parameters.Arguments;
}
```
- Deserializes executable and arguments parameters
- Combines executable and arguments into single command line
- Supports both JSON and space-separated parameter formats

#### 2. Command Line Parsing
```csharp
private string[] ParseCommandLine(string cmdline)
{
    int numberOfArgs;
    IntPtr ptrToSplitArgs;
    string[] splitArgs;

    ptrToSplitArgs = _pCommandLineToArgvW(cmdline, out numberOfArgs);
    if (ptrToSplitArgs == IntPtr.Zero)
        return null;

    try
    {
        splitArgs = new string[numberOfArgs];
        for (int i = 0; i < numberOfArgs; i++)
            splitArgs[i] = Marshal.PtrToStringUni(
                Marshal.ReadIntPtr(ptrToSplitArgs, i * IntPtr.Size));
        return splitArgs;
    }
    finally
    {
        _pLocalFree(ptrToSplitArgs);
    }
}
```
- Uses Windows `CommandLineToArgvW` API for proper command-line parsing
- Handles quoted arguments and special characters correctly
- Properly frees allocated memory using `LocalFree`
- Returns null on parsing failure

#### 3. Process Creation and Configuration
```csharp
string[] parts = ParseCommandLine(mythiccmd);
string app = parts[0];
string cmdline = null;
if (parts.Length > 1)
{
    cmdline = mythiccmd.Replace(app, "").TrimStart();
}

proc = _agent.GetProcessManager().NewProcess(app, cmdline);
proc.OutputDataReceived += DataReceived;
proc.ErrorDataReceieved += DataReceived;
proc.Exit += Proc_Exit;
```
- Separates application path from arguments
- Creates process using Apollo's process manager
- Registers event handlers for output, error, and exit events
- Enables real-time output capture

#### 4. Process Execution and Monitoring
```csharp
bool bRet = proc.Start();
if (!bRet)
{
    // Handle start failure
}
else
{
    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("", false, "", 
        new IMythicMessage[] { Artifact.ProcessCreate((int) proc.PID, app, cmdline) }));
    
    while(proc != null && !proc.HasExited && !_cancellationToken.IsCancellationRequested)
    {
        WaitHandle.WaitAny(new WaitHandle[] { _complete, _cancellationToken.Token.WaitHandle }, 500);
    }
}
```
- Starts the process and checks for success
- Creates process creation artifact with PID and command line
- Monitors process execution with 500ms polling intervals
- Supports cancellation through cancellation token

#### 5. Output Handling
```csharp
private void DataReceived(object sender, ApolloInterop.Classes.Events.StringDataEventArgs e)
{
    if (!string.IsNullOrEmpty(e.Data))
    {
        _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(e.Data, false, ""));
    }
}
```
- Captures both stdout and stderr output
- Streams output in real-time as intermediate responses
- Filters empty output to reduce noise

#### 6. Process Cleanup
```csharp
private void Proc_Exit(object sender, EventArgs e)
{
    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("", true));
    _complete.Set();
}

if (proc != null && !proc.HasExited)
{
    proc.Kill();
    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("", true));
}
```
- Handles normal process exit through event handler
- Kills process if still running when task is cancelled
- Ensures proper task completion in all scenarios

### API Function Resolution

#### Required APIs
```csharp
public run(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
{
    _pLocalFree = _agent.GetApi().GetLibraryFunction<LocalFree>(Library.KERNEL32, "LocalFree");
    _pCommandLineToArgvW = _agent.GetApi().GetLibraryFunction<CommandLineToArgvW>(Library.SHELL32, "CommandLineToArgvW");
}
```
- Resolves `CommandLineToArgvW` from Shell32 for command parsing
- Resolves `LocalFree` from Kernel32 for memory cleanup
- Uses Apollo's dynamic API resolution framework

### Process Manager Integration

The command leverages Apollo's process manager which handles:
- **PATH Resolution**: Automatic executable location via %PATH%
- **Process Creation**: Platform-appropriate process spawning
- **Output Redirection**: Capture of stdout and stderr streams
- **Process Lifecycle**: Management of process state and cleanup

### Command Line Parsing Features

#### Windows-Style Parsing
- **Quoted Arguments**: Properly handles `"argument with spaces"`
- **Escape Sequences**: Processes backslash escaping
- **Special Characters**: Handles pipes, redirects, and other shell characters
- **Empty Arguments**: Preserves empty quoted strings

#### PATH Resolution
- **Executable Search**: Uses Windows PATH environment variable
- **File Extensions**: Automatically appends .exe, .cmd, .bat as needed
- **Current Directory**: Searches current working directory first
- **Full Paths**: Supports absolute paths bypassing PATH search

### Data Structures

#### RunParameters
```csharp
struct RunParameters
{
    public string Executable; // Executable name or path
    public string Arguments;  // Command-line arguments
}
```

### Real-Time Output Features

#### Output Streaming
- **Immediate Display**: Output appears as it's generated
- **Bidirectional Capture**: Both stdout and stderr streams
- **Event-Driven**: Uses event handlers for efficient processing
- **Non-Blocking**: Doesn't wait for process completion to show output

#### Process Monitoring
- **Status Tracking**: Monitors process execution state
- **Exit Detection**: Detects process termination
- **Cancellation Support**: Can interrupt long-running processes
- **Resource Management**: Proper cleanup on all exit paths

## APIs Used
| API | Purpose | DLL |
|-----|---------|-----|
| `CommandLineToArgvW` | Parse command line into arguments | shell32.dll |
| `LocalFree` | Free memory allocated by Windows | kernel32.dll |
| `Marshal.PtrToStringUni` | Convert Unicode pointer to string | mscorlib.dll |
| `Marshal.ReadIntPtr` | Read pointer from memory | mscorlib.dll |

## MITRE ATT&CK Mapping
- **T1106** - Native API
- **T1218** - Signed Binary Proxy Execution
- **T1553** - Subvert Trust Controls

## Security Considerations
- **Code Execution**: Direct execution of arbitrary binaries
- **Output Exposure**: Command output transmitted back to operator
- **Process Artifacts**: Creates process creation events in system logs
- **PATH Exploitation**: May execute unintended binaries via PATH manipulation

## Limitations
1. Subject to execution policies and security software
2. Requires executable to exist and be accessible
3. Output capture depends on proper stream redirection
4. Long-running processes may impact agent performance
5. Some console applications may not work properly
6. Binary execution subject to user permissions

## Error Conditions
- **File Not Found**: Executable not found in PATH or specified location
- **Access Denied**: Insufficient permissions to execute binary
- **Command Parse Error**: `CommandLineToArgvW` fails to parse command line
- **Process Start Failure**: Process creation fails with Win32 error
- **Memory Allocation**: Failed to allocate memory for argument parsing