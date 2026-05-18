+++
title = "ps"
chapter = false
weight = 103
hidden = false
+++

## Summary
Enumerates all running processes with detailed information including process metadata, user context, architecture, integrity levels, and command-line arguments using parallel processing for optimal performance.

- **Needs Admin:** False
- **Version:** 3
- **Author:** @djhohnstein

### Arguments
None

## Usage
```
ps
```

**Raw Output:**
```json
[
  {
    "pid": 1234,
    "name": "notepad",
    "username": "DOMAIN\\alice",
    "parent_process_id": 5678,
    "architecture": "x64",
    "process_path": "C:\\Windows\\System32\\notepad.exe",
    "integrity_level": 2,
    "session_id": 1,
    "command_line": "notepad.exe document.txt",
    "description": "Notepad",
    "company_name": "Microsoft Corporation",
    "window_title": "document.txt - Notepad"
  }
]
```

**Formatted Output:**
![ps](../images/ps.png)

## Detailed Summary

### Agent Execution Flow

#### 1. API Function Resolution
```csharp
public ps(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
{
    try
    {
        _pIsWow64Process2 = _agent.GetApi().GetLibraryFunction<IsWow64Process2>(Library.KERNEL32, "IsWow64Process2");   
    } catch
    {
        _pIsWow64Process = _agent.GetApi().GetLibraryFunction<IsWow64Process>(Library.KERNEL32, "IsWow64Process");
    }
    _pOpenProcessToken = _agent.GetApi().GetLibraryFunction<OpenProcessToken>(Library.ADVAPI32, "OpenProcessToken");
    _pNtQueryInformationProcess = _agent.GetApi().GetLibraryFunction<NtQueryInformationProcess>(Library.NTDLL, "NtQueryInformationProcess");
}
```
- Attempts to resolve modern `IsWow64Process2` API, falls back to `IsWow64Process`
- Resolves token and process information APIs
- Uses Apollo's dynamic API resolution framework

#### 2. Parallel Process Enumeration
```csharp
TT.ParallelOptions po = new TT.ParallelOptions();
po.CancellationToken = _cancellationToken.Token;
po.MaxDegreeOfParallelism = System.Environment.ProcessorCount;

TT.Parallel.ForEach(System.Diagnostics.Process.GetProcesses(), (proc) =>
{
    po.CancellationToken.ThrowIfCancellationRequested();
    ProcessInformation current = new ProcessInformation();
    // Process each process concurrently
});
```
- Uses parallel processing with degree equal to processor count
- Supports cancellation through cancellation token
- Processes all system processes concurrently for performance

#### 3. Process User Extraction
```csharp
public string GetProcessUser(IntPtr procHandle)
{
    try
    {
        IntPtr tokenHandle = IntPtr.Zero;
        _ = _pOpenProcessToken(procHandle, TokenAccessLevels.MaximumAllowed, out procHandle);
        return new WindowsIdentity(procHandle).Name;
    }
    catch
    {
        return "";
    }
}
```
- Opens process token with maximum allowed access
- Creates WindowsIdentity to extract username
- Handles access denied exceptions gracefully

#### 4. Parent Process ID Retrieval
```csharp
public int GetParentProcess(IntPtr procHandle)
{
    try
    {
        ProcessBasicInformation procinfo = new ProcessBasicInformation();
        _ = _pNtQueryInformationProcess(procHandle, 0, ref procinfo, Marshal.SizeOf(procinfo), out _);
        return procinfo.InheritedFromUniqueProcessId.ToInt32();
    }
    catch
    {
        return -1;
    }
}
```
- Uses `NtQueryInformationProcess` with information class 0 (basic information)
- Extracts parent process ID from `ProcessBasicInformation` structure
- Returns -1 on failure

#### 5. Architecture Detection
```csharp
if (_pIsWow64Process2 != null)
{
    if (_pIsWow64Process2(proc.Handle, out IMAGE_FILE_MACHINE_ processMachine, out _))
    {
        switch (processMachine)
        {
            case IMAGE_FILE_MACHINE_.IMAGE_FILE_MACHINE_UNKNOWN:
                current.Architecture = "x64";
                break;
            case IMAGE_FILE_MACHINE_.IMAGE_FILE_MACHINE_I386:
                current.Architecture = "x86";
                break;
        }
    }
}
else
{
    if (_pIsWow64Process(proc.Handle, out bool IsWow64))
    {
        current.Architecture = IsWow64 ? "x86" : "x64";
    }
}
```
- Prefers modern `IsWow64Process2` for detailed architecture information
- Falls back to `IsWow64Process` on older systems
- Maps machine types to readable architecture strings

#### 6. Integrity Level Extraction
```csharp
private string GetIntegrityLevel(IntPtr procHandle)
{
    IntPtr hProcToken;
    Result = _pOpenProcessToken(procHandle, TokenAccessLevels.Query, out hProcToken);
    Result = _pGetTokenInformation(hProcToken, TokenInformationClass.TokenIntegrityLevel, TokenInformation, TokenInfLength, out TokenInfLength);
    pTIL = (TokenMandatoryLevel)Marshal.PtrToStructure(TokenInformation, typeof(TokenMandatoryLevel));
    _pConvertSidToStringSid(pTIL.Label.Sid, out sidString);
}
```
- Opens process token for query access
- Retrieves token integrity level information
- Converts integrity level SID to string format
- Maps to integer levels (0=Untrusted, 1=Low, 2=Medium, 3=High)

#### 7. Command Line Retrieval
```csharp
private string GetProcessCommandLine(int processId)
{
    using (ManagementObjectSearcher mos = new ManagementObjectSearcher(
        String.Format("SELECT CommandLine FROM Win32_Process WHERE ProcessId = {0}", processId)))
    {
        foreach (ManagementObject mo in mos.Get())
        {
            if (mo.GetPropertyValue("CommandLine") != null)
            {
                result = mo.GetPropertyValue("CommandLine").ToString();
                result = Uri.UnescapeDataString(result);
                break;
            }
        }
    }
}
```
- Uses WMI to query process command line
- Handles processes without command line information
- URL-decodes command line for proper display

#### 8. Comprehensive Metadata Collection
```csharp
try
{
    current.ProcessPath = proc.MainModule.FileVersionInfo.FileName;
    current.Description = proc.MainModule.FileVersionInfo.FileDescription;
    current.CompanyName = proc.MainModule.FileVersionInfo.CompanyName;
    current.WindowTitle = proc.MainWindowTitle;
    current.SessionId = proc.SessionId;
}
catch
{
    // Handle access denied for protected processes
}
```
- Extracts file version information from main module
- Captures window title for GUI applications
- Records session ID for session tracking
- Handles exceptions for protected processes

### Data Structures

#### ProcessInformation
```csharp
struct ProcessInformation
{
    public int PID;                    // Process ID
    public string Name;                // Process name
    public string Username;            // Process owner
    public int ParentProcessId;        // Parent process ID
    public string Architecture;        // x86/x64
    public string ProcessPath;         // Full executable path
    public int IntegrityLevel;         // 0-3 integrity level
    public int SessionId;              // User session ID
    public string CommandLine;         // Command line arguments
    public string Description;         // File description
    public string CompanyName;         // Software vendor
    public string WindowTitle;         // Main window title
    public bool UpdateDeleted;         // Update flag
}
```

#### ProcessBasicInformation (Native)
```csharp
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct ProcessBasicInformation
{
    internal IntPtr ExitStatus;
    internal IntPtr PebBaseAddress;
    internal IntPtr AffinityMask;
    internal IntPtr BasePriority;
    internal UIntPtr UniqueProcessId;
    internal IntPtr InheritedFromUniqueProcessId;  // Parent PID
}
```

### Integrity Level Mapping
```csharp
private int GetIntegerIntegrityLevel(string il)
{
    switch (il)
    {
        case "S-1-16-0":    return 0;     // Untrusted
        case "S-1-16-4096": return 1;     // Low
        case "S-1-16-8192": return 2;     // Medium
        case "S-1-16-12288": return 3;    // High
        case "S-1-16-16384": return 3;    // System
        case "S-1-16-20480": return 3;    // Protected Process
        case "S-1-16-28672": return 3;    // Secure Process
    }
}
```

### Performance Optimization
- **Parallel Processing**: Uses all available CPU cores
- **Exception Handling**: Graceful degradation for inaccessible processes
- **Thread Safety**: Thread-safe collections for concurrent access
- **Cancellation Support**: Honors cancellation requests during enumeration

## APIs Used
| API | Purpose | DLL |
|-----|---------|-----|
| `Process.GetProcesses()` | Enumerate all processes | System.Diagnostics |
| `OpenProcessToken` | Open process token | advapi32.dll |
| `NtQueryInformationProcess` | Get process basic information | ntdll.dll |
| `GetTokenInformation` | Get token details | advapi32.dll |
| `IsWow64Process2` | Determine process architecture | kernel32.dll |
| `IsWow64Process` | Determine WoW64 status (fallback) | kernel32.dll |
| `ConvertSidToStringSid` | Convert integrity SID | advapi32.dll |
| `ManagementObjectSearcher` | WMI query for command lines | System.Management |

## MITRE ATT&CK Mapping
- **T1106** - Native API
- **T1057** - Process Discovery

## Security Considerations
- **Information Disclosure**: Reveals detailed process information
- **System Reconnaissance**: Provides comprehensive system state view
- **Process Monitoring**: Shows all running processes and their relationships
- **User Context**: Exposes process ownership and privilege levels

## Limitations
1. Some process information requires appropriate privileges
2. Protected processes may deny access to certain metadata
3. WMI queries for command lines may be slow on some systems
4. Integrity level extraction requires token query access
5. Parallel processing may impact system performance temporarily

## Error Conditions
- **Access Denied**: Insufficient privileges for protected processes
- **Process Termination**: Processes may exit during enumeration
- **WMI Failures**: Management queries may fail for some processes
- **Token Access**: Token operations may fail for system processes
- **API Unavailability**: Some APIs may not exist on older systems