+++
title = "sc"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: None
{{% /notice %}}

## Summary
.NET implementation of the Service Control Manager binary `sc.exe` for querying, starting, stopping, creating, deleting, and modifying Windows services on local and remote systems. Provides comprehensive service management capabilities with detailed service information and interactive UI features.

- **Needs Admin:** False (some operations require elevated privileges)
- **Version:** 3
- **Author:** @djhohnstein

### Arguments
The `sc` command supports multiple operation modes through parameter groups:

#### Query Mode
- **query** (Boolean) - Query services on target system
- **computer** (String, Optional) - Target computer name
- **service** (String, Optional) - Specific service name to query
- **display_name** (String, Optional) - Service display name filter

![query](../images/sc_query.png)

#### Start Mode
- **start** (Boolean) - Start specified service
- **service** (String, Required) - Service name to start
- **computer** (String, Optional) - Target computer name

![start](../images/sc_start.png)

#### Stop Mode
- **stop** (Boolean) - Stop specified service
- **service** (String, Required) - Service name to stop
- **computer** (String, Optional) - Target computer name

![stop](../images/sc_stop.png)

#### Create Mode
- **create** (Boolean) - Create new service
- **service** (String, Required) - Service name
- **display_name** (String, Required) - Service display name
- **binpath** (String, Required) - Path to service executable
- **computer** (String, Optional) - Target computer name

![create](../images/sc_create.png)

#### Delete Mode
- **delete** (Boolean) - Delete specified service
- **service** (String, Required) - Service name to delete
- **computer** (String, Optional) - Target computer name

![delete](../images/sc_delete.png)


#### Modify Mode
- **modify** (Boolean) - Modify existing service
- **service** (String, Required) - Service name to modify
- **computer** (String, Optional) - Target computer name
- **binpath** (String, Optional) - New binary path
- **display_name** (String, Optional) - New display name
- **description** (String, Optional) - Service description
- **run_as** (String, Optional) - Service account username
- **password** (String, Optional) - Service account password
- **service_type** (String, Optional) - Service type
- **start_type** (String, Optional) - Service start type
- **dependencies** (String Array, Optional) - Service dependencies

![delete](../images/sc_modify.png)

## Usage
```
# Query all services locally
sc -Query

# Query specific service
sc -Query -ServiceName "Spooler"

# Query services on remote computer
sc -Query -Computer DC01

# Start a service
sc -Start -ServiceName "Spooler"

# Stop a service on remote computer
sc -Stop -ServiceName "Spooler" -Computer DC01

# Create a new service
sc -Create -ServiceName "MyService" -DisplayName "My Custom Service" -BinPath "C:\MyService.exe"

# Delete a service
sc -Delete -ServiceName "MyService"

# Modify service binary path
sc -Modify -ServiceName "MyService" -BinPath "C:\NewPath\MyService.exe"
```

**Output:**
```
Interactive table with columns:
- Actions (Start/Stop/Delete/Modify/More Info buttons)
- Status (Running/Stopped/etc.)
- PID (Process ID if running)
- Service Name
- Display Name
- Binary Path
```

## Detailed Summary

### Agent Execution Flow

#### 1. Parameter Processing and Validation
```csharp
[DataContract]
internal struct ScParameters
{
    [DataMember(Name = "query")] public bool Query;
    [DataMember(Name = "start")] public bool Start;
    [DataMember(Name = "stop")] public bool Stop;
    [DataMember(Name = "create")] public bool Create;
    [DataMember(Name = "delete")] public bool Delete;
    [DataMember(Name = "modify")] public bool Modify;
    [DataMember(Name = "computer")] public string Computer;
    [DataMember(Name = "service")] public string Service;
    [DataMember(Name = "display_name")] public string DisplayName;
    [DataMember(Name = "binpath")] public string Binpath;
    [DataMember(Name = "run_as")] public string RunAs;
    [DataMember(Name = "password")] public string Password;
    [DataMember(Name = "service_type")] public string ServiceTypeParam;
    [DataMember(Name = "start_type")] public string StartType;
    [DataMember(Name = "dependencies")] public string[] Dependencies;
    [DataMember(Name = "description")] public string Description;
}
```
- Deserializes parameters from JSON input
- Validates required parameters for each operation mode
- Sets default computer name to local machine if not specified
- Ensures mutual exclusivity of operation modes

#### 2. Parameter Validation Logic
```csharp
private void ValidateParameters(ScParameters args)
{
    if (args.Start && string.IsNullOrEmpty(args.Service))
        throw new Exception("Start action requires service name to start.");
    
    if (args.Stop && string.IsNullOrEmpty(args.Service))
        throw new Exception("Stop action requires service name to stop.");
    
    if (args.Create && (string.IsNullOrEmpty(args.Service) || string.IsNullOrEmpty(args.Binpath)))
        throw new Exception("Create action requires service name and binpath.");
    
    if (args.Delete && string.IsNullOrEmpty(args.Service))
        throw new Exception("Delete action requires service name to delete.");
    
    if (args.Modify && string.IsNullOrEmpty(args.Service))
        throw new Exception("Modify action requires service name to modify.");
}
```
- Validates required parameters for each operation mode
- Prevents execution with incomplete parameter sets
- Provides clear error messages for missing requirements

#### 3. Service Control Manager Connection
```csharp
ServiceControlHandle OpenSCManager(string lpMachineName, string lpSCDB, SCMAccess scParameter)

ServiceControlHandle serviceMangerHandle = _pOpenSCManager(
    parameters.Computer, 
    null, 
    SCMAccess.SC_MANAGER_ENUMERATE_SERVICE
);

if (serviceMangerHandle.IsInvalid)
    throw new Exception($"Failed to open SCM: {new Win32Exception().Message}");
```
- Opens connection to Service Control Manager on target system
- Uses appropriate access rights based on operation type
- Handles connection failures with detailed error messages
- Supports both local and remote service management

#### 4. Service Enumeration (Query Mode)
```csharp
private static List<ServiceResult> QueryServies(ScParameters parameters, string action)
{
    // First call to get buffer size needed
    bool result = _pEnumServicesStatusEx(
        serviceMangerHandle,
        ServiceInfoLevel.SC_ENUM_PROCESS_INFO,
        (int) ServiceType.SERVICE_WIN32,
        (int) ServiceStateRequest.SERVICE_STATE_ALL,
        IntPtr.Zero,
        0,
        out uint iBytesNeeded,
        out uint iServicesReturned,
        ref iResumeHandle,
        null);

    // Allocate memory and get actual service data
    buf = Marshal.AllocHGlobal((int) iBytesNeeded);
    result = _pEnumServicesStatusEx(/* ... with allocated buffer ... */);
    
    // Parse results into service objects
    ENUM_SERVICE_STATUS_PROCESS[] serviceArray = GetServiceStatuses(buf, iServicesReturned);
}
```
- Enumerates all services on target system
- Uses two-phase approach: size calculation then data retrieval
- Handles memory allocation and deallocation properly
- Supports filtering by service name when specified

#### 5. Service Configuration Retrieval
```csharp
private static QUERY_SERVICE_CONFIG GetServiceConfig(ServiceControlHandle serviceHandle)
{
    // Get required buffer size
    bool retCode = _pQueryServiceConfig(serviceHandle, IntPtr.Zero, 0, out uint bytesNeeded);
    
    // Allocate and retrieve configuration
    IntPtr qscPtr = Marshal.AllocCoTaskMem((int)bytesNeeded);
    retCode = _pQueryServiceConfig(serviceHandle, qscPtr, bytesNeeded, out bytesNeeded);
    
    return (QUERY_SERVICE_CONFIG)Marshal.PtrToStructure(qscPtr, typeof(QUERY_SERVICE_CONFIG));
}

private static string GetServiceDescription(ServiceControlHandle serviceHandle)
{
    _pQueryServiceConfig2(serviceHandle, ConfigInfoLevel.SERVICE_CONFIG_DESCRIPTION, 
        IntPtr.Zero, 0, out uint dwBytesNeeded);
    
    IntPtr ptr = Marshal.AllocHGlobal((int)dwBytesNeeded);
    bool success = _pQueryServiceConfig2(serviceHandle, ConfigInfoLevel.SERVICE_CONFIG_DESCRIPTION, 
        ptr, dwBytesNeeded, out dwBytesNeeded);
    
    SERVICE_DESCRIPTION sd = new SERVICE_DESCRIPTION();
    Marshal.PtrToStructure(ptr, sd);
    return sd.lpDescription;
}
```
- Retrieves detailed service configuration information
- Gets service description through separate API call
- Properly manages memory allocation for variable-length data
- Handles configuration retrieval failures gracefully

#### 6. Service State Management
```csharp
// Service Start Operation
ServiceController instance = new ServiceController(parameters.Service, parameters.Computer);
if (instance.Status == ServiceControllerStatus.Running)
{
    // Service already running
}
else
{
    instance.Start();
    ST.Task waitForServiceAsync = new ST.Task(() => { 
        instance.WaitForStatus(ServiceControllerStatus.Running); 
    }, _cancellationToken.Token);
    waitForServiceAsync.Start();
}

// Service Stop Operation
ServiceController stopInstance = new ServiceController(parameters.Service, parameters.Computer);
if (stopInstance.Status == ServiceControllerStatus.Stopped)
{
    // Service already stopped
}
else
{
    stopInstance.Stop();
    ST.Task stopTask = new ST.Task(() => { 
        stopInstance.WaitForStatus(ServiceControllerStatus.Stopped); 
    });
}
```
- Uses .NET ServiceController class for state management
- Implements asynchronous waiting for state changes
- Supports cancellation during state transitions
- Provides feedback on current service state

#### 7. Service Creation and Installation
```csharp
private static bool InstallService(string hostname, string ServiceName, string ServiceDisplayName, string ServiceEXE)
{
    // Remove existing service if present
    try { UninstallService(hostname, ServiceName); }
    catch (Exception) { }
    
    ServiceControlHandle scmHandle = _pOpenSCManager(hostname, null, SCMAccess.SC_MANAGER_CREATE_SERVICE);
    ServiceControlHandle serviceHandle = _pCreateService(
        scmHandle,
        ServiceName,
        ServiceDisplayName,
        ServiceAccess.SERVICE_ALL_ACCESS,
        ServiceType.SERVICE_WIN32_OWN_PROCESS,
        ServiceStartType.SERVICE_AUTO_START,
        ServiceErrorControl.SERVICE_ERROR_NORMAL,
        ServiceEXE,
        null,           // LoadOrderGroup
        IntPtr.Zero,    // TagId
        null,           // Dependencies
        null,           // ServiceStartName
        null);          // Password
    
    return !serviceHandle.IsInvalid;
}
```
- Creates new Windows service with specified parameters
- Automatically removes existing service with same name
- Uses standard service configuration defaults
- Provides comprehensive error handling

#### 8. Service Modification
```csharp
private static void ModifyService(ScParameters parameters)
{
    const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
    
    ServiceControlHandle serviceHandle = _pOpenService(serviceMangerHandle, parameters.Service, 
        ServiceAccess.SERVICE_CHANGE_CONFIG);
    
    // Prepare modification parameters
    uint newServiceType = SERVICE_NO_CHANGE;
    uint newStartType = SERVICE_NO_CHANGE;
    string newBinPath = parameters.Binpath;
    string newDisplayName = parameters.DisplayName;
    string newServiceStartName = parameters.RunAs;
    string newPassword = parameters.Password;
    
    // Handle dependencies array
    string newDepends = null;
    if (parameters.Dependencies != null)
    {
        foreach (string depend in parameters.Dependencies)
            newDepends += depend + "\0";
        newDepends += "\0";
    }
    
    // Apply changes
    bool success = _pChangeServiceConfig(serviceHandle, newServiceType, newStartType, 
        SERVICE_NO_CHANGE, newBinPath, null, IntPtr.Zero, newDepends, 
        newServiceStartName, newPassword, newDisplayName);
    
    // Set description separately
    if (!string.IsNullOrEmpty(parameters.Description))
        SetServiceDescription(serviceHandle, parameters.Description);
}
```
- Modifies existing service configuration
- Supports partial updates using SERVICE_NO_CHANGE constant
- Handles dependencies as null-terminated string array
- Updates service description through separate API call

#### 9. Interactive UI Features
```csharp
// Browser script generates interactive table with action buttons
{
    "actions": {"button": {
        "name": "Actions",
        "type": "menu",
        "startIcon": "list",
        "value": [
            {
                "name": "Start",
                "type": "task",
                "ui_feature": "sc:start",
                "parameters": JSON.stringify({
                    "start": true,
                    "computer": jinfo["computer"],
                    "service": jinfo["service"]
                }),
                "disabled": !isStart,
                "hoverText": "Start Service"
            },
            // ... additional buttons for Stop, Delete, Modify, More Info
        ]
    }}
}
```
- Generates interactive table with action buttons
- Buttons are enabled/disabled based on service state
- Supports direct service management from UI
- Provides detailed service information in popup dialogs

### API Function Resolution

#### Required Windows APIs
```csharp
public sc(IAgent agent, MythicTask data) : base(agent, data)
{
    _pDeleteService = _agent.GetApi().GetLibraryFunction<DeleteService>(Library.ADVAPI32, "DeleteService");
    _pOpenService = _agent.GetApi().GetLibraryFunction<OpenService>(Library.ADVAPI32, "OpenServiceA");
    _pStartService = _agent.GetApi().GetLibraryFunction<StartService>(Library.ADVAPI32, "StartServiceA");
    _pCloseServiceHandle = _agent.GetApi().GetLibraryFunction<CloseServiceHandle>(Library.ADVAPI32, "CloseServiceHandle");
    _pOpenSCManager = _agent.GetApi().GetLibraryFunction<OpenSCManager>(Library.ADVAPI32, "OpenSCManagerA");
    _pCreateService = _agent.GetApi().GetLibraryFunction<CreateService>(Library.ADVAPI32, "CreateServiceA");
    _pControlService = _agent.GetApi().GetLibraryFunction<ControlService>(Library.ADVAPI32, "ControlService");
    _pEnumServicesStatusEx = _agent.GetApi().GetLibraryFunction<EnumServicesStatusEx>(Library.ADVAPI32, "EnumServicesStatusExW");
    _pQueryServiceConfig2 = _agent.GetApi().GetLibraryFunction<QueryServiceConfig2>(Library.ADVAPI32, "QueryServiceConfig2W");
    _pQueryServiceConfig = _agent.GetApi().GetLibraryFunction<QueryServiceConfig>(Library.ADVAPI32, "QueryServiceConfigW");
    _pChangeServiceConfig = _agent.GetApi().GetLibraryFunction<ChangeServiceConfig>(Library.ADVAPI32, "ChangeServiceConfigA");
    _pChangeServiceConfig2 = _agent.GetApi().GetLibraryFunction<ChangeServiceConfig2>(Library.ADVAPI32, "ChangeServiceConfig2W");
}
```
- Dynamically resolves all required service management APIs
- Uses both ANSI and Unicode variants as appropriate
- Leverages Apollo's API resolution framework
- Provides comprehensive service management capabilities

### Data Structures

#### ServiceResult Output Structure
```csharp
[DataContract]
internal struct ServiceResult
{
    [DataMember(Name = "display_name")] public string DisplayName;
    [DataMember(Name = "service")] public string Service;
    [DataMember(Name = "status")] public string Status;
    [DataMember(Name = "can_stop")] public bool CanStop;
    [DataMember(Name = "dependencies")] public string[] Dependencies;
    [DataMember(Name = "service_type")] public string SvcType;
    [DataMember(Name = "start_type")] public string StartType;
    [DataMember(Name = "description")] public string Description;
    [DataMember(Name = "computer")] public string Computer;
    [DataMember(Name = "binary_path")] public string BinaryPath;
    [DataMember(Name = "load_order_group")] public string LoadOrderGroup;
    [DataMember(Name = "run_as")] public string RunAs;
    [DataMember(Name = "error_control")] public string ErrorControl;
    [DataMember(Name = "pid")] public string PID;
    [DataMember(Name = "accepted_controls")] public string[] AcceptedControls;
    [DataMember(Name = "action")] public string Action;
}
```

#### Memory Management
```csharp
[SecurityPermission(SecurityAction.InheritanceDemand, UnmanagedCode = true)]
[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
public class ServiceControlHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private ServiceControlHandle() : base(true) { }

    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
    protected override bool ReleaseHandle()
    {
        return _pCloseServiceHandle(this.handle);
    }
}
```
- Implements proper handle management through SafeHandle
- Ensures automatic cleanup of service handles
- Provides constrained execution region guarantees
- Prevents handle leaks in error scenarios

### Service Type and State Enumerations

#### Service Types
```csharp
[Flags]
public enum ServiceType : uint
{
    SERVICE_KERNEL_DRIVER = 0x1,
    SERVICE_FILE_SYSTEM_DRIVER = 0x2,
    SERVICE_WIN32_OWN_PROCESS = 0x10,
    SERVICE_WIN32_SHARE_PROCESS = 0x20,
    SERVICE_INTERACTIVE_PROCESS = 0x100,
    SERVICE_WIN32 = (SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS)
}
```

#### Service States
```csharp
public enum SERVICE_STATE : uint
{
    SERVICE_STOPPED = 0x00000001,
    SERVICE_START_PENDING = 0x00000002,
    SERVICE_STOP_PENDING = 0x00000003,
    SERVICE_RUNNING = 0x00000004,
    SERVICE_CONTINUE_PENDING = 0x00000005,
    SERVICE_PAUSE_PENDING = 0x00000006,
    SERVICE_PAUSED = 0x00000007
}
```

#### Service Start Types
```csharp
public enum ServiceStartType : uint
{
    SERVICE_AUTO_START = 0x00000002,
    SERVICE_BOOT_START = 0x00000000,
    SERVICE_DEMAND_START = 0x00000003,
    SERVICE_DISABLED = 0x00000004,
    SERVICE_SYSTEM_START = 0x00000001
}
```

## APIs Used
| API | Purpose | DLL |
|-----|---------|-----|
| `OpenSCManagerA` | Open Service Control Manager | advapi32.dll |
| `OpenServiceA` | Open handle to specific service | advapi32.dll |
| `CreateServiceA` | Create new service | advapi32.dll |
| `DeleteService` | Delete existing service | advapi32.dll |
| `StartServiceA` | Start service | advapi32.dll |
| `ControlService` | Send control codes to service | advapi32.dll |
| `EnumServicesStatusExW` | Enumerate services with detailed info | advapi32.dll |
| `QueryServiceConfigW` | Query service configuration | advapi32.dll |
| `QueryServiceConfig2W` | Query extended service configuration | advapi32.dll |
| `ChangeServiceConfigA` | Modify service configuration | advapi32.dll |
| `ChangeServiceConfig2W` | Modify extended service configuration | advapi32.dll |
| `CloseServiceHandle` | Close service handles | advapi32.dll |

## MITRE ATT&CK Mapping
- **T1106** - Native API
- **T1543.003** - Create or Modify System Process: Windows Service
- **T1569.002** - System Services: Service Execution

## Security Considerations
- **Privilege Escalation**: Service creation/modification may require admin rights
- **Persistence**: Services can be used for maintaining persistence
- **Service Hijacking**: Modification of existing services for malicious purposes
- **Remote Access**: Can manage services on remote systems
- **Credential Exposure**: Service account credentials may be visible in memory

## Limitations
1. Some operations require administrative privileges
2. Remote service management depends on network connectivity and permissions
3. Service state changes may take time to complete
4. Some services cannot be stopped due to system dependencies
5. Service creation requires valid executable path
6. Password changes may require service restart

## Error Conditions
- **Access Denied**: Insufficient privileges for requested operation
- **Service Not Found**: Specified service does not exist
- **Invalid Parameter**: Missing required parameters for operation
- **SCM Connection Failed**: Cannot connect to Service Control Manager
- **Service Start/Stop Timeout**: Service fails to change state within timeout period
- **Handle Creation Failed**: Cannot obtain handle to service or SCM
- **Configuration Error**: Invalid service configuration parameters
- **Network Error**: Remote service management fails due to network issues