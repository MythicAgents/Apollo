using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;
using ApolloInterop.Serializers;
using System.Threading;
using System.IO;
using System.Security.AccessControl;
using TT = System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Management;
using static ApolloInterop.Enums.Win32;
using System.Security.Principal;
using ApolloInterop.Classes.Api;
using ApolloInterop.Classes.Collections;

namespace Tasks
{
    public class ps : Tasking
    {
        private delegate bool OpenProcessToken(
            IntPtr hProcess,
            TokenAccessLevels dwAccess,
            out IntPtr hToken);

        private delegate bool NtQueryInformationProcess(
            IntPtr hProcess,
            int dwInformationClass,
            ref ProcessBasicInformation pProcessInformation,
            int dwProcessInformationLength,
            out int dwLength);

        private delegate bool GetTokenInformation(
            IntPtr TokenHandle,
            TokenInformationClass TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);
        private delegate bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);
        private delegate bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        private IsWow64Process _pIsWow64Process;
        private OpenProcessToken _pOpenProcessToken;
        private NtQueryInformationProcess _pNtQueryInformationProcess;
        private GetTokenInformation _pGetTokenInformation;
        private ConvertSidToStringSid _pConvertSidToStringSid;

        public ps(IAgent agent, Task task) : base(agent, task)
        {
            _pIsWow64Process = _agent.GetApi().GetLibraryFunction<IsWow64Process>(Library.KERNEL32, "IsWow64Process");
            _pOpenProcessToken = _agent.GetApi().GetLibraryFunction<OpenProcessToken>(Library.ADVAPI32, "OpenProcessToken");
            _pNtQueryInformationProcess = _agent.GetApi().GetLibraryFunction<NtQueryInformationProcess>(Library.NTDLL, "NtQueryInformationProcess");
            _pGetTokenInformation = _agent.GetApi().GetLibraryFunction<GetTokenInformation>(Library.ADVAPI32, "GetTokenInformation");
            _pConvertSidToStringSid = _agent.GetApi().GetLibraryFunction<ConvertSidToStringSid>(Library.ADVAPI32, "ConvertSidToStringSidW");
        }


        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct ProcessBasicInformation
        {
            internal IntPtr ExitStatus;
            internal IntPtr PebBaseAddress;
            internal IntPtr AffinityMask;
            internal IntPtr BasePriority;
            internal UIntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;
        }
        public const UInt32 TOKEN_QUERY = 0x0008;

        [StructLayout(LayoutKind.Sequential)]
        internal struct TokenMandatoryLevel
        {

            public SidAndAttributes Label;

        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SidAndAttributes
        {
            public IntPtr Sid;
            public int Attributes;
        }

        public string GetProcessUser(IntPtr procHandle)
        {
            try
            {
                IntPtr tokenHandle = IntPtr.Zero;
                _ = _pOpenProcessToken(
                    procHandle,                                 // ProcessHandle
                    TokenAccessLevels.MaximumAllowed,     // desiredAccess
                    out procHandle);                            // TokenHandle
                return new WindowsIdentity(procHandle).Name;
            }
            catch // If we can't open a handle to the process it will throw an exception
            {
                return "";
            }
        }

        public int GetParentProcess(IntPtr procHandle)
        {
            try
            {
                ProcessBasicInformation procinfo = new ProcessBasicInformation();
                _ = _pNtQueryInformationProcess(
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

        private string GetProcessCommandLine(int processId)
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

        private int GetIntegerIntegrityLevel(string il)
        {
            int result = 0;
            switch (il)
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

        private string GetIntegrityLevel(IntPtr procHandle)
        {
            // Returns all SIDs that the current user is a part of, whether they are disabled or not.
            // slightly adapted from https://stackoverflow.com/questions/2146153/how-to-get-the-logon-sid-in-c-sharp/2146418#2146418
            IntPtr hProcToken;
            var TokenInfLength = 0;
            TokenMandatoryLevel pTIL;
            IntPtr StructPtr;
            bool Result = false;
            string sidString;
            long dwIntegrityLevel = 0;
            try
            {
                Result = _pOpenProcessToken(procHandle, TokenAccessLevels.Query, out hProcToken);
            }
            catch
            {
                return "";
            }
            if (!Result) return "";
            // first call gets length of TokenInformation
            Result = _pGetTokenInformation(hProcToken, TokenInformationClass.TokenIntegrityLevel, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            var TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
            Result = _pGetTokenInformation(hProcToken, TokenInformationClass.TokenIntegrityLevel, TokenInformation, TokenInfLength, out TokenInfLength);

            if (!Result)
            {
                Marshal.FreeHGlobal(TokenInformation);
                return "";
            }
            pTIL = (TokenMandatoryLevel)Marshal.PtrToStructure(TokenInformation, typeof(TokenMandatoryLevel));
            if (!_pConvertSidToStringSid(pTIL.Label.Sid, out sidString))
            {
                sidString = "";
            }
            Marshal.FreeHGlobal(TokenInformation);

            return sidString;
        }

        public override void Kill()
        {
            _cancellationToken.Cancel();
        }

        public override System.Threading.Tasks.Task CreateTasking()
        {
            return new System.Threading.Tasks.Task(() =>
            {
                ThreadSafeList<ProcessInformation> processes = new ThreadSafeList<ProcessInformation>();
                TT.ParallelOptions po = new TT.ParallelOptions();
                po.CancellationToken = _cancellationToken.Token;
                po.MaxDegreeOfParallelism = System.Environment.ProcessorCount;
                try
                {
                    TT.Parallel.ForEach(System.Diagnostics.Process.GetProcesses(), (proc) =>
                    {
                        po.CancellationToken.ThrowIfCancellationRequested();
                        ProcessInformation current = new ProcessInformation();
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
                            _pIsWow64Process(proc.Handle, out bool is64);
                            arch = is64 ? "x64" : "x86";
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
                        current.PID = proc.Id;
                        current.Architecture = arch;
                        current.Name = proc.ProcessName;
                        current.Username = processUser;
                        current.ProcessPath = filePath;
                        current.CommandLine = commandLine;
                        current.Description = desc;
                        current.Signer = desc;
                        current.SessionId = sessionId;
                        current.WindowTitle = windowTitle;
                        processes.Add(current);
                    });
                } catch (OperationCanceledException)
                {

                }
                ProcessInformation[] all = processes.Flush();
                IMythicMessage[] procs = new IMythicMessage[all.Length];

                Array.Copy(all, procs, all.Length);
                
                
                TaskResponse resp = CreateTaskResponse(
                    _jsonSerializer.Serialize(all),
                    true,
                    "completed",
                    procs);
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }, _cancellationToken.Token);
        }
    }
}
