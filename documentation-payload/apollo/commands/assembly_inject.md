+++
title = "assembly_inject"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Inject
{{% /notice %}}

## Summary
The `assembly_inject` function injects a .NET assembly loader into a remote process and executes a registered .NET assembly within that process context. This capability enables operators to execute .NET assemblies in the memory space of other processes, providing stealth and the security context benefits of the target process for post-exploitation activities. The command leverages Apollo's configurable injection techniques and establishes inter-process communication through named pipes.

- **Needs Admin:** False (but injection into certain processes may require elevated privileges)
- **Version:** 3
- **Author:** @djhohnstein

### Arguments
- **pid** (Number) - Process ID of the target process to inject into
- **assembly_name** (ChooseOne) - Name of the .NET assembly registered with `register_file` command (e.g., Seatbelt.exe)
- **assembly_arguments** (String, optional) - Command-line arguments to pass to the assembly during execution

### Arguments (Positional or Popup)

![args](../images/assembly_inject.png)

## Usage
### Example 1: Basic Assembly Injection
**Command:**
```
assembly_inject -PID 7344 -Assembly Seatbelt.exe -Arguments DotNet
```
**Output:**
```text
Successfully injected assembly loader into PID 7344
Process injection artifact generated using CreateRemoteThread
Establishing named pipe communication: pipe_12345678-abcd-ef01-2345-6789abcdef01
Connected to injected loader, sending assembly data...
Assembly Seatbelt.exe loaded successfully
Executing with arguments: DotNet

=== Assembly Output ===
[Seatbelt output continues here...]

Assembly execution completed successfully
```

### Example 2: Assembly Without Arguments
**Command:**
```
assembly_inject -PID 4892 -Assembly SharpHound.exe
```
**Output:**
```text
Successfully injected assembly loader into PID 4892
Process injection artifact generated using QueueUserAPC
Establishing named pipe communication: pipe_87654321-dcba-10fe-5432-ba9876543210
Connected to injected loader, sending assembly data...
Assembly SharpHound.exe loaded successfully
Executing with no arguments

=== Assembly Output ===
[SharpHound enumeration output...]

Assembly execution completed successfully
```

### Example 3: Injection Failure - Process Not Running
**Command:**
```
assembly_inject -PID 99999 -Assembly Seatbelt.exe
```
**Output:**
```text
Error: Process with ID 99999 is not running.
```

### Example 4: Assembly Not Registered
**Command:**
```
assembly_inject -PID 7344 -Assembly UnknownTool.exe
```
**Output:**
```text
Error: UnknownTool.exe is not loaded (have you registered it?)
```

### Example 5: Injection Failure - Access Denied
**Command:**
```
assembly_inject -PID 4 -Assembly Seatbelt.exe
```
**Output:**
```text
Error: Failed to inject into PID 4
```

## Detailed Summary

The `assembly_inject` function implements a sophisticated approach to in-memory .NET assembly execution within remote processes, operating through a multi-stage workflow that combines process injection, inter-process communication, and assembly loading:

### 1. Parameter Validation and Preprocessing

The function begins with comprehensive validation of all input parameters:

* **Assembly Registration Verification**: Checks that the specified assembly name exists in the agent's file store using `_agent.GetFileManager().GetFileFromStore()` which retrieves DPAPI-encrypted AES256 cached assemblies
* **Process Validation**: Verifies the target process ID corresponds to a running process using `System.Diagnostics.Process.GetProcessById()` with exception handling for non-existent PIDs
* **Parameter Completeness Check**: Ensures all required parameters (PID, assembly name, pipe name, loader stub ID) are provided through the `AssemblyInjectParameters` structure
* **Assembly Arguments Processing**: Handles optional assembly arguments, defaulting to empty string if not provided

### 2. Injection Preparation and Stub Generation

The Python command handler prepares the necessary injection components:

* **ExecuteAssembly.exe Compilation**: If not already present, the handler compiles the ExecuteAssembly.exe loader stub from source using `dotnet build` with release configuration
* **Donut Shellcode Generation**: Uses the Donut framework to convert ExecuteAssembly.exe into position-independent shellcode with the pipe name as a parameter: `donut.create(file=EXEECUTE_ASSEMBLY_PATH, params=taskData.args.get_arg("pipe_name"))`
* **Named Pipe Generation**: Creates a unique named pipe identifier using `uuid4()` for secure inter-process communication
* **File Registration**: Registers the generated shellcode with Mythic's file management system for download by the agent

### 3. Process Injection Execution

The core injection operation uses Apollo's injection management system:

```csharp
var injector = _agent.GetInjectionManager().CreateInstance(exeAsmPic, parameters.PID);
if (injector.Inject())
{
    // Generate artifact and proceed with communication
}
```

**Supported Injection Techniques** (based on Apollo's actual implementation):
* **CreateRemoteThread**: Standard remote thread creation injection
* **QueueUserAPC (Early Bird)**: Asynchronous Procedure Call injection into process threads
* **Syscall_x64.NtCreateThreadEx**: Direct syscall-based thread creation for enhanced evasion

**Injection Process Flow**:
* **Technique Selection**: Uses the currently configured injection technique via `get_injection_techniques`/`set_injection_technique`
* **Shellcode Injection**: Injects the Donut-generated shellcode containing the ExecuteAssembly loader
* **Execution Trigger**: Initiates execution of the injected payload within the target process
* **Artifact Generation**: Creates a process injection artifact using `Artifact.ProcessInject()` for tracking and reporting

### 4. Inter-Process Communication Setup

The function establishes secure communication with the injected ExecuteAssembly loader:

* **Named Pipe Client Creation**: Instantiates an `AsyncNamedPipeClient` connecting to "127.0.0.1" with the generated pipe name
* **Event Handler Registration**: Configures handlers for:
  - `ConnectionEstablished`: Starts sender and message flushing threads
  - `MessageReceived`: Processes assembly output messages
  - `Disconnect`: Handles cleanup and completion signaling
* **Connection Establishment**: Attempts to connect to the named pipe with a 10-second timeout using `client.Connect(10000)`
* **Threading Model**: Uses separate threads for data transmission (`_sendAction`) and message processing (`_flushMessages`)

### 5. Assembly Data Transmission

Once communication is established, the function transmits the assembly and arguments:

```csharp
IPCCommandArguments cmdargs = new IPCCommandArguments
{
    ByteData = assemblyBytes,
    StringData = string.IsNullOrEmpty(parameters.AssemblyArguments) ? "" : parameters.AssemblyArguments,
};
```

**Transmission Process**:
* **Data Serialization**: Uses `JsonSerializer` to convert command arguments into IPC format
* **Data Chunking**: Breaks large assemblies into manageable chunks using `SerializeIPCMessage()`
* **Asynchronous Transmission**: Sends data chunks asynchronously through the named pipe using `BeginWrite()`
* **Flow Control**: Uses `AutoResetEvent` signaling to coordinate data transmission between threads

### 6. Assembly Execution and Output Handling

The injected ExecuteAssembly loader executes the assembly and streams output back:

* **Assembly Loading**: The injected loader receives assembly bytes and loads them into the target process memory using `Assembly.Load()`
* **Execution Context**: Executes the assembly within the security and privilege context of the target process
* **Output Streaming**: Captures all console output from the assembly and streams it back through the named pipe
* **Real-time Processing**: Processes and displays output in real-time as it's received from the injected process

### 7. Message Processing and Output Management

The function implements thread-safe message handling:

```csharp
private void Client_MessageReceived(object sender, NamedPipeMessageArgs e)
{
    IPCData d = e.Data;
    string msg = Encoding.UTF8.GetString(d.Data.Take(d.DataLength).ToArray());
    _assemblyOutput.Add(msg);
}
```

**Output Management Features**:
* **Thread-Safe Collection**: Uses `ThreadSafeList<string>` to safely collect output from multiple threads
* **Periodic Flushing**: The `_flushMessages` thread regularly flushes collected output to the task response queue with 1-second intervals
* **UTF-8 Decoding**: Properly decodes received message data from UTF-8 encoding
* **Message Aggregation**: Combines multiple message fragments into coherent output blocks

### 8. Connection Lifecycle Management

The function carefully manages the entire communication lifecycle:

* **Connection Monitoring**: Continuously monitors pipe connection status using `ps.IsConnected` and cancellation tokens
* **Graceful Shutdown**: Handles disconnection events through `Client_Disconnect` which closes pipes and sets completion events
* **Resource Disposal**: Properly closes pipe connections and disposes of resources via `e.Pipe.Close()`
* **Completion Signaling**: Uses `AutoResetEvent` objects (`_complete`) to coordinate completion between threads

### 9. Error Handling and Recovery

Comprehensive error handling covers multiple failure scenarios:

* **Process Validation Failures**: Reports when target processes are not running or accessible with specific error messages
* **Assembly Registration Issues**: Identifies when assemblies are not registered with clear "have you registered it?" messaging
* **Injection Failures**: Handles and reports injection technique failures with process-specific error information
* **Communication Failures**: Manages named pipe connection failures with timeout handling
* **Assembly Execution Errors**: Captures and reports errors from assembly execution within the target process

### 10. Artifact Generation and Tracking

The function integrates with Mythic's artifact tracking system:

* **Process Injection Artifacts**: Automatically generates artifacts documenting the injection event using `Artifact.ProcessInject()`
* **Technique Documentation**: Records the specific injection technique used for the operation
* **Timeline Integration**: Ensures artifacts are properly timestamped and associated with the task
* **Audit Trail**: Provides complete audit trail of injection activities for post-operation analysis

## MITRE ATT&CK Mapping
- **T1055** - Process Injection
  - **T1055.002** - Portable Executable Injection
  - **T1055.004** - Asynchronous Procedure Call

## Technical Deep Dive

### ExecuteAssembly Loader Architecture

The ExecuteAssembly.exe loader implements a streamlined approach to in-process assembly execution:

#### Donut Shellcode Generation
```python
# Python command handler generates shellcode using Donut
donutPic = donut.create(file=EXEECUTE_ASSEMBLY_PATH, params=taskData.args.get_arg("pipe_name"))
```

**Donut Framework Integration**:
- **Position Independence**: Generates position-independent code that can execute from any memory location
- **Parameter Embedding**: Embeds the named pipe name directly into the shellcode for communication
- **Self-Extraction**: The shellcode automatically extracts and initializes the ExecuteAssembly loader
- **Minimal Footprint**: Optimized shellcode size for stealthy injection

#### Named Pipe Communication Protocol

The communication protocol implements a structured approach to data exchange:

```csharp
public class IPCCommandArguments
{
    public byte[] ByteData;    // Assembly binary data
    public string StringData;  // Command-line arguments
}
```

**Protocol Features**:
- **Binary Data Support**: Efficiently transfers large assembly binaries through `ByteData`
- **Chunked Transmission**: Breaks large data into manageable chunks via `SerializeIPCMessage()`
- **Flow Control**: Implements proper flow control using `AutoResetEvent` signaling
- **Error Recovery**: Handles partial transmission failures and connection issues

### Injection Technique Integration

Apollo's injection management system provides flexibility in technique selection:

#### Supported Injection Techniques
Based on Apollo's actual implementation, the following techniques are available:

1. **CreateRemoteThread**
   - Standard Windows API for remote thread creation
   - Widely supported across Windows versions
   - Good compatibility with most target processes

2. **QueueUserAPC (Early Bird)**
   - Asynchronous Procedure Call injection
   - Targets threads in alertable wait states
   - Effective for evading some detection mechanisms

3. **Syscall_x64.NtCreateThreadEx**
   - Direct syscall-based thread creation
   - Enhanced evasion through syscall usage
   - Bypasses some API hooking mechanisms

#### Dynamic Technique Selection
```csharp
// Technique selection managed through injection manager
var injector = _agent.GetInjectionManager().CreateInstance(shellcode, targetPID);
string techniqueName = _agent.GetInjectionManager().GetCurrentTechnique().Name;
```

**Selection Features**:
- **Configuration-Based**: Uses the technique set via `set_injection_technique`
- **Consistent Application**: All post-exploitation jobs use the same configured technique
- **Runtime Switching**: Techniques can be changed between operations

### File Caching and Security

Apollo implements secure file caching for assemblies:

#### DPAPI Encryption
```csharp
// Files are cached using DPAPI encrypted AES256 blobs
_agent.GetFileManager().GetFileFromStore(assemblyName, out byte[] assemblyBytes)
```

**Security Features**:
- **DPAPI Protection**: Files are encrypted using Windows DPAPI (Data Protection API)
- **AES256 Encryption**: Additional AES256 encryption layer for enhanced security
- **User-Specific**: DPAPI ensures files are only accessible to the current user context
- **Memory-Only**: Assembly execution occurs entirely in memory without disk writes

#### Cache Management
- **Persistent Storage**: Assemblies remain cached across agent restarts
- **Efficient Retrieval**: Fast retrieval through file manager interface
- **Size Limitations**: No size limitations on cached assemblies
- **Cleanup**: Cached files are properly cleaned up during agent termination

### Threading and Concurrency

The implementation uses sophisticated threading for optimal performance:

#### Asynchronous Operations
```csharp
// Asynchronous pipe operations prevent blocking
pipe.BeginWrite(data, 0, data.Length, OnAsyncMessageSent, pipe);
```

**Threading Model**:
- **Sender Thread**: Dedicated thread for data transmission (`_sendAction`)
- **Receiver Thread**: Automatic message processing through event handlers
- **Flush Thread**: Periodic output flushing (`_flushMessages`)
- **Non-Blocking I/O**: All pipe operations use asynchronous patterns

#### Synchronization Mechanisms
- **AutoResetEvent**: Coordinates thread communication and completion
- **ConcurrentQueue**: Thread-safe queuing for message transmission
- **ThreadSafeList**: Secure collection of assembly output messages
- **Cancellation Tokens**: Proper cancellation support for long-running operations

## APIs Used and Their Purposes
| API | Purpose | DLL | Documentation |
|------|---------|-----|--------------|
| `System.Diagnostics.Process.GetProcessById` | Validates target process existence | System.dll | [Process.GetProcessById](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process.getprocessbyid) |
| `IAgent.GetFileManager().GetFileFromStore()` | Retrieves DPAPI-encrypted cached assemblies | Apollo Agent | Internal Apollo API |
| `IAgent.GetInjectionManager().CreateInstance()` | Creates injection instance using current technique | Apollo Agent | Internal Apollo API |
| `AsyncNamedPipeClient.Connect()` | Establishes named pipe communication | Apollo Agent | Internal Apollo IPC API |
| `Assembly.Load()` | Loads .NET assembly from byte array | mscorlib.dll | [Assembly.Load](https://docs.microsoft.com/en-us/dotnet/api/system.reflection.assembly.load) |
| `Encoding.UTF8.GetString()` | Decodes UTF-8 byte data to strings | mscorlib.dll | [Encoding.GetString](https://docs.microsoft.com/en-us/dotnet/api/system.text.encoding.getstring) |
| `AutoResetEvent.WaitOne()` | Thread synchronization and signaling | mscorlib.dll | [AutoResetEvent.WaitOne](https://docs.microsoft.com/en-us/dotnet/api/system.threading.autoresetevent.waitone) |
| `ConcurrentQueue<T>.TryDequeue()` | Thread-safe queue operations | System.Collections.Concurrent.dll | [ConcurrentQueue](https://docs.microsoft.com/en-us/dotnet/api/system.collections.concurrent.concurrentqueue-1) |
| `PipeStream.BeginWrite()` | Asynchronous named pipe write operations | System.Core.dll | [PipeStream.BeginWrite](https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.pipestream.beginwrite) |

## Security Considerations

### Process Selection Strategy
1. **Target Process Choice**: Select processes with appropriate privileges and stability (e.g., explorer.exe, svchost.exe)
2. **Process Integrity**: Avoid injecting into critical system processes that may cause system instability
3. **User Context**: Consider the security context of the target process for operation success
4. **Detection Avoidance**: Choose processes that are less likely to be monitored by security tools

### Assembly Security
1. **DPAPI Protection**: Assemblies are protected using DPAPI encryption while cached
2. **Memory-Only Execution**: Assembly execution occurs entirely in memory without disk writes
3. **Dependency Management**: Verify all assembly dependencies are available in the target process
4. **Version Compatibility**: Ensure assembly .NET Framework version compatibility with target process

### Communication Security
1. **Pipe Name Randomization**: Named pipes use UUID4 for cryptographically random names
2. **Local Communication**: Named pipes are bound to localhost (127.0.0.1) only
3. **No Authentication**: Named pipes do not implement additional authentication mechanisms
4. **Data Integrity**: No additional encryption is applied to pipe communications

### Injection Technique Security
1. **Technique Diversity**: Multiple injection techniques available to evade detection
2. **Syscall Evasion**: Syscall_x64.NtCreateThreadEx provides enhanced evasion capabilities
3. **API Hooking Bypass**: Direct syscalls can bypass some API monitoring solutions
4. **Process Compatibility**: Different techniques have varying compatibility with target processes

### Audit Trail Considerations
Process injection activities may generate various audit events:
- **Event 4688**: Process creation events for spawned processes
- **Event 4656**: Object access events for process handles
- **Sysmon Events**: Modern detection solutions may generate additional events for injection activities
- **ETW Tracing**: Enhanced logging may capture injection-related activities

## Limitations

1. **Assembly Dependencies**: Assemblies with external dependencies may fail to load in the target process
2. **Architecture Compatibility**: x86/x64 architecture mismatches between agent and target process will cause failures
3. **Process Permissions**: Insufficient privileges may prevent injection into certain processes (e.g., SYSTEM processes)
4. **Injection Technique Compatibility**: Not all injection techniques work reliably with all process types
5. **Assembly Registration**: Assemblies must be pre-registered using `register_file` command before use
6. **Named Pipe Limits**: Windows has limits on concurrent named pipe connections
7. **Memory Constraints**: Extremely large assemblies may cause memory pressure in target processes
8. **Framework Limitations**: Target processes must have compatible .NET Framework versions loaded

## Troubleshooting

### Common Issues and Solutions

| Issue | Possible Causes | Solutions |
|-------|----------------|-----------|
| "Process not running" | Invalid PID, process terminated | Verify PID with `ps` command, check process status |
| "Assembly not loaded" | Assembly not registered | Use `register_file` to register assembly first |
| "Failed to inject" | Insufficient privileges, incompatible process | Try different target process, run `getprivs`, check process architecture |
| "Named pipe connection failed" | Injection successful but communication failed | Verify injection technique compatibility, check process stability |
| "Assembly execution failed" | Missing dependencies, version mismatch | Verify assembly dependencies and .NET Framework compatibility |
| "Operation timed out" | Injection or communication timeout | Check target process health, try different injection technique |

### Debugging Steps
1. **Verify Process Status**: Use `ps` command to confirm target process is running and note its architecture
2. **Check Assembly Registration**: Use `register_file` to ensure assembly is properly cached
3. **Test Injection Technique**: Use `get_injection_techniques` to verify current technique and try alternatives with `set_injection_technique`
4. **Monitor System Resources**: Check memory usage and process stability during operation
5. **Review Injection Compatibility**: Test with different target processes to identify compatibility issues
6. **Validate Assembly**: Test assembly execution with `inline_assembly` first to verify it works correctly

### Injection Technique Troubleshooting
- **CreateRemoteThread**: Most compatible but easily detected
- **QueueUserAPC**: Requires target process threads in alertable wait states
- **Syscall_x64.NtCreateThreadEx**: Best evasion but may have compatibility issues with some processes

## References

- [Process Injection Techniques](https://attack.mitre.org/techniques/T1055/)
- [.NET Assembly Loading](https://docs.microsoft.com/en-us/dotnet/standard/loading-assemblies)
- [Windows Named Pipes](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
- [Donut Shellcode Generator](https://github.com/TheWover/donut)
- [Apollo Agent Source Code](https://github.com/MythicAgents/Apollo)
- [Windows DPAPI](https://docs.microsoft.com/en-us/windows/win32/api/dpapi/)
- [Process Injection Detection](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)