#define COMMAND_NAME_UPPER

#if DEBUG
#undef PS
#undef PS_FULL
#define PS
#define PS_FULL
#endif

#if PS || PS_FULL

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Apollo.Jobs;
using System.Management;
using static Native.Methods;
using static Native.Constants;
using static Native.Enums;
using static Native.Structures;
using System.Threading;
using Apollo.Tasks;

namespace Apollo.CommandModules
{
    public class ProcessList
    {
        // These PInvoke definitions and structs are artifacts
        // of when there was a semblance of hope these modules
        // may be delivered independently. This is no longer the case.

        public const UInt32 TOKEN_QUERY = 0x0008;

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_MANDATORY_LABEL
        {

            public SID_AND_ATTRIBUTES Label;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

#if PS_FULL
        /// <summary>
        /// Given an open process handle with TOKEN_QUERY privileges,
        /// return the integrity level the process is running under
        /// as a string.
        /// </summary>
        /// <param name="procHandle">Open process handle with TOKEN_QUERY privileges.</param>
        /// <returns>String of the integrity level.</returns>
        private static string GetIntegrityLevel(IntPtr procHandle)
        {
            // Returns all SIDs that the current user is a part of, whether they are disabled or not.
            // slightly adapted from https://stackoverflow.com/questions/2146153/how-to-get-the-logon-sid-in-c-sharp/2146418#2146418
            IntPtr hProcToken;
            var TokenInfLength = 0;
            TOKEN_MANDATORY_LABEL pTIL;
            IntPtr StructPtr;
            bool Result = false;
            string sidString;
            long dwIntegrityLevel = 0;
            try
            {
                Result = OpenProcessToken(procHandle, 8, out hProcToken);
            }
            catch
            {
                return "";
            }
            if (!Result) return "";
            // first call gets length of TokenInformation
            Result = GetTokenInformation(hProcToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            var TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
            Result = GetTokenInformation(hProcToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, TokenInformation, TokenInfLength, out TokenInfLength);

            if (!Result)
            {
                Marshal.FreeHGlobal(TokenInformation);
                return "";
            }
            pTIL = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_MANDATORY_LABEL));
            if (!ConvertSidToStringSid(pTIL.Label.Sid, out sidString))
            {
                sidString = "";
            }
            Marshal.FreeHGlobal(TokenInformation);

            return sidString;
        }
#endif
#if PS_FULL
        /// <summary>
        /// Given a process ID, retrieve the command line the process
        /// was launched with via WMI. 
        /// </summary>
        /// <param name="processId">The ID of the process to retrieve the command line for.</param>
        /// <returns>Command line arguments of the string.</returns>
        private static string GetProcessCommandLine(int processId)
        {
            string result = "";
            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher(
String.Format("SELECT CommandLine FROM Win32_Process WHERE ProcessId = {0}", processId)))

                {
                    foreach (ManagementObject mo in mos.Get())

                    {
                        if (mo.GetPropertyValue("CommandLine") != null)
                        {
                            result = mo.GetPropertyValue("CommandLine").ToString();
                            break;
                        }
                    }
                }
            }
            catch { }
            return result;
        }
#endif

        /// <summary>
        /// Retrieve a rich process listing of current processes
        /// executing on the system. This will retrieve all data
        /// associated with the Apfell.Structs.ProcessEntry structure.
        /// </summary>
        /// <param name="job">Job associated with this task.</param>
        /// <param name="agent">Agent associated with this task.</param>
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            List<Mythic.Structs.ProcessEntry> procList = new List<Mythic.Structs.ProcessEntry>();
            List<Thread> threadList = new List<Thread>();
            Mutex mtx = new Mutex();
            bool fullDetails = false;
            switch(task.command)
            {
#if PS
                case "ps":
                    fullDetails = false;
                    break;
#endif
#if PS_FULL
                case "ps_full":
                    fullDetails = true;
                    break;
#endif
                default:
                    job.SetError("Unsupported code path reached.");
                    return;
            }
            foreach (System.Diagnostics.Process proc in System.Diagnostics.Process.GetProcesses())
            {
                Thread t = new Thread(() => AddApfellProcessEntry(proc, ref procList, ref mtx, fullDetails));
                t.Start();
                threadList.Add(t);
            }
            foreach (Thread t in threadList)
            {
                t.Join();
            }

            job.SetComplete(procList.ToArray());
        }

        /// <summary>
        /// Helper function to populate a process list with valid
        /// Apfell structures.
        /// </summary>
        /// <param name="proc">Process to convert into an Apfell.Structs.ProcessEntry</param>
        /// <param name="procList">Reference to a list to populate with valid ProcessEntry structures.</param>
        /// <param name="mtx">Mutex to ensure procList is not being modified simultaneously by another Thread.</param>
        public static void AddApfellProcessEntry(System.Diagnostics.Process proc, ref List<Mythic.Structs.ProcessEntry> procList, ref Mutex mtx, bool fullDetails = false)
        {
            string arch = "";
            string integrityLevel = "";
            int sessionId = -1;
            string commandLine = "";
            string desc = "";
            string companyName = "";
            string processUser = "";
            int parentProcessId = -1;
            string filePath = "";
            string windowTitle = "";
            try
            {
                processUser = GetProcessUser(proc.Handle);
            }
            catch
            {
                processUser = "";
            }
            try
            {
                parentProcessId = GetParentProcess(proc.Handle);
            }
            catch
            {
                parentProcessId = -1;
            }
            try
            {
                IsWow64Process(proc.Handle, out bool is64);
                if (is64) arch = "x86";
                else arch = "x64";
            }
            catch { arch = ""; }
            try
            {
                filePath = proc.MainModule.FileVersionInfo.FileName;
            }
            catch
            {
                filePath = "";
            }
#if PS_FULL
            if (fullDetails)
            {
                try
                {
                    integrityLevel = GetIntegrityLevel(proc.Handle);
                }
                catch
                {
                    integrityLevel = ""; // probably redundant
                }
                try
                {
                    sessionId = proc.SessionId;
                }
                catch
                {
                    sessionId = -1;
                }
                try
                {
                    commandLine = GetProcessCommandLine(proc.Id);
                }
                catch
                {
                    commandLine = "";
                }
                try
                {
                    desc = proc.MainModule.FileVersionInfo.FileDescription;
                }
                catch
                {
                    desc = "";
                }
                try
                {
                    companyName = proc.MainModule.FileVersionInfo.CompanyName;
                }
                catch
                {
                    companyName = "";
                }
                try
                {
                    windowTitle = proc.MainWindowTitle;
                }
                catch
                {
                    windowTitle = "";
                }
            }
#endif
            Mythic.Structs.ProcessEntry procEntry = new Mythic.Structs.ProcessEntry()
            {
                process_id = proc.Id,
                name = proc.ProcessName,
                parent_process_id = parentProcessId,
                user = processUser,
                architecture = arch,
                integrity_level = GetIntegerIntegrityLevel(integrityLevel),
                integrity_level_string = integrityLevel,
                description = desc,
                signer = companyName,
                session = sessionId,
                command_line = commandLine,
                bin_path = filePath,
                window_title = windowTitle
            };
            try
            {
                mtx.WaitOne();
                procList.Add(procEntry);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(String.Format("Exception occurred while adding to list: {0}", ex.Message));
            }
            finally
            {
                mtx.ReleaseMutex();
            }
        }

        private static int GetIntegerIntegrityLevel(string il)
        {
            int result = 0;
            switch(il)
            {
                case "S-1-16-0":
                    result = 0;
                    break;
                case "S-1-16-4096":
                    result = 1;
                    break;
                case "S-1-16-8192":
                    result = 2;
                    break;
                case "S-1-16-12288":
                    result = 3;
                    break;
                case "S-1-16-16384":
                    result = 3;
                    break;
                case "S-1-16-20480":
                    result = 3;
                    break;
                case "S-1-16-28672":
                    result = 3;
                    break;
                default:
                    break;
            }
            return result;
        }

        // No way of getting parent process from C#, but we can use NtQueryInformationProcess to get this info.
        /// <summary>
        /// Retrieve the parent PID of an open process handle.
        /// </summary>
        /// <param name="procHandle">Open process handle to investigate.</param>
        /// <returns>-1 if unsuccessful, otherwise the PID of the parent process.</returns>
        public static int GetParentProcess(IntPtr procHandle)
        {
            try
            {
                PROCESS_BASIC_INFORMATION procinfo = new PROCESS_BASIC_INFORMATION();
                _ = NtQueryInformationProcess(
                    procHandle,                 // ProcessHandle
                    0,                          // processInformationClass
                    ref procinfo,               // ProcessBasicInfo
                    Marshal.SizeOf(procinfo),   // processInformationLength
                    out _);                     // returnLength
                return procinfo.InheritedFromUniqueProcessId.ToInt32();
            }
            catch
            {
                return -1;
            }
        }

        /// <summary>
        /// Given a process handle, retrieve the user associated with
        /// that process.
        /// </summary>
        /// <param name="procHandle">Open handle to a process for data to be retrieved from</param>
        /// <returns>Username as string.</returns>
        public static string GetProcessUser(IntPtr procHandle)
        {
            try
            {
                IntPtr tokenHandle = IntPtr.Zero;
                _ = OpenProcessToken(
                    procHandle,                                 // ProcessHandle
                    (uint)TokenAccessLevels.MaximumAllowed,     // desiredAccess
                    out procHandle);                            // TokenHandle
                return new WindowsIdentity(procHandle).Name;
            }
            catch // If we can't open a handle to the process it will throw an exception
            {
                return "";
            }
        }
    }
}
#endif