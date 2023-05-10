#define COMMAND_NAME_UPPER

#if DEBUG
#define PS
#endif

#if PS

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
        #region delegates
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
        private delegate bool IsWow64Process2(IntPtr hProcess, out IMAGE_FILE_MACHINE_ pProcessMachine, out IMAGE_FILE_MACHINE_ pNativeMachine);
        private delegate bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        private IsWow64Process2 _pIsWow64Process2 = null;
        private IsWow64Process _pIsWow64Process = null;
        private OpenProcessToken _pOpenProcessToken;
        private NtQueryInformationProcess _pNtQueryInformationProcess;
        private GetTokenInformation _pGetTokenInformation;
        private ConvertSidToStringSid _pConvertSidToStringSid;

        enum IMAGE_FILE_MACHINE_
        {
            IMAGE_FILE_MACHINE_UNKNOWN = 0,
            IMAGE_FILE_MACHINE_TARGET_HOST = 0x001,
            IMAGE_FILE_MACHINE_I386 = 0x014c,
            IMAGE_FILE_MACHINE_R3000_LE = 0x0162,
            IMAGE_FILE_MACHINE_R3000_BE = 0x160,
            IMAGE_FILE_MACHINE_R4000_LE = 0x0166,
            IMAGE_FILE_MACHINE_R10000_LE = 0x0168,
            IMAGE_FILE_MACHINE_WCEMIPSV2_LE = 0x0169,
            IMAGE_FILE_MACHINE_ALPHA = 0x0184,
            IMAGE_FILE_MACHINE_SH3_LE = 0x01a2,
            IMAGE_FILE_MACHINE_SH3DSP = 0x01a3,
            IMAGE_FILE_MACHINE_SH3E_LE = 0x01a4,
            IMAGE_FILE_MACHINE_SH4_LE = 0x01a6,
            IMAGE_FILE_MACHINE_SH5 = 0x01a8,
            IMAGE_FILE_MACHINE_ARM_LE = 0x01c0,
            IMAGE_FILE_MACHINE_THUMB_LE = 0x01c2,
            IMAGE_FILE_MACHINE_ARMNT_LE = 0x01c4,
            IMAGE_FILE_MACHINE_AM33 = 0x01d3,
            IMAGE_FILE_MACHINE_POWERPC = 0x01F0,
            IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1,
            IMAGE_FILE_MACHINE_IA64 = 0x0200,
            IMAGE_FILE_MACHINE_MIPS16 = 0x0266,
            IMAGE_FILE_MACHINE_ALPHA64 = 0x0284,
            IMAGE_FILE_MACHINE_MIPSFPU = 0x0366,
            IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466,
            IMAGE_FILE_MACHINE_AXP64 = 0x0284,
            IMAGE_FILE_MACHINE_TRICORE = 0x0520,
            IMAGE_FILE_MACHINE_CEF = 0x0CEF,
            IMAGE_FILE_MACHINE_EBC = 0x0EBC,
            IMAGE_FILE_MACHINE_AMD64 = 0x8664,
            IMAGE_FILE_MACHINE_M32R_LE = 0x9041,
            IMAGE_FILE_MACHINE_ARM64_LE = 0xAA64,
            IMAGE_FILE_MACHINE_CEE = 0xC0EE,
        };
        
        #endregion

        private Action<object> _flushMessages;
        private ThreadSafeList<ProcessInformation> _processes = new ThreadSafeList<ProcessInformation>();
        private AutoResetEvent _completed = new AutoResetEvent(false);
        private bool _complete = false;
        public ps(IAgent agent, Task task) : base(agent, task)
        {
            try
            {
                _pIsWow64Process2 = _agent.GetApi().GetLibraryFunction<IsWow64Process2>(Library.KERNEL32, "IsWow64Process2");   
            } catch
            {
                _pIsWow64Process = _agent.GetApi().GetLibraryFunction<IsWow64Process>(Library.KERNEL32, "IsWow64Process");
            }
            _pOpenProcessToken = _agent.GetApi().GetLibraryFunction<OpenProcessToken>(Library.ADVAPI32, "OpenProcessToken");
            _pNtQueryInformationProcess = _agent.GetApi().GetLibraryFunction<NtQueryInformationProcess>(Library.NTDLL, "NtQueryInformationProcess");
            _pGetTokenInformation = _agent.GetApi().GetLibraryFunction<GetTokenInformation>(Library.ADVAPI32, "GetTokenInformation");
            _pConvertSidToStringSid = _agent.GetApi().GetLibraryFunction<ConvertSidToStringSid>(Library.ADVAPI32, "ConvertSidToStringSidA");
            _flushMessages = (object o) =>
            {
                ProcessInformation[] output = null;
                while (!_cancellationToken.IsCancellationRequested && !_complete)
                {
                    WaitHandle.WaitAny(new WaitHandle[]
                    {
                        _completed,
                        _cancellationToken.Token.WaitHandle
                    }, 1000);
                    output = _processes.Flush();
                    if (output.Length > 0)
                    {
                        SendProcessInfo(output);
                    }
                }
                output = _processes.Flush();
                if (output.Length > 0)
                {
                    SendProcessInfo(output);
                }
            };
        }

        private void SendProcessInfo(ProcessInformation[] output)
        {
            IMythicMessage[] procs = new IMythicMessage[output.Length];
            Array.Copy(output, procs, procs.Length);
            _agent.GetTaskManager().AddTaskResponseToQueue(
                CreateTaskResponse(
                    _jsonSerializer.Serialize(output),
                    false,
                    "",
                    procs));
        }

        #region helpers
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
        #endregion


        public override void Start()
        {
            TT.Task.Factory.StartNew(_flushMessages, _cancellationToken);
            TT.ParallelOptions po = new TT.ParallelOptions();
            po.CancellationToken = _cancellationToken.Token;
            po.MaxDegreeOfParallelism = System.Environment.ProcessorCount;
            try
            {
                TT.Parallel.ForEach(System.Diagnostics.Process.GetProcesses(), (proc) =>
                {
                    po.CancellationToken.ThrowIfCancellationRequested();
                    ProcessInformation current = new ProcessInformation();
                    current.PID = proc.Id;
                    current.Name = proc.ProcessName;
                    try
                    {
                        current.Username = GetProcessUser(proc.Handle);
                    }
                    catch
                    {
                        current.Username = "";
                    }

                    try
                    {
                        current.ParentProcessId = GetParentProcess(proc.Handle);
                    }
                    catch
                    {
                        current.ParentProcessId = -1;
                    }

                    try
                    {
                        if (_pIsWow64Process2 != null)
                        {
                            if (_pIsWow64Process2(proc.Handle, out IMAGE_FILE_MACHINE_ processMachine, out _))
                            {
                                switch (processMachine)
                                {
                                    case IMAGE_FILE_MACHINE_.IMAGE_FILE_MACHINE_UNKNOWN:
                                        current.Architecture = "x64";
                                        break;
                                    case IMAGE_FILE_MACHINE_.IMAGE_FILE_MACHINE_I386:
                                        current.Architecture = "x86";
                                        break;
                                    default:
                                        current.Architecture = "x86";
                                        break;
                                }   
                            }
                            else
                            {
                                current.Architecture = "";
                            }
                        }
                        else
                        {
                            if (_pIsWow64Process(proc.Handle, out bool IsWow64))
                            {
                                current.Architecture = IsWow64 ? "x86" : "x64";
                            }
                            else
                            {
                                current.Architecture = "";
                            }
                        }
                    }
                    catch
                    {
                        current.Architecture = "";
                    }

                    try
                    {
                        current.ProcessPath = proc.MainModule.FileVersionInfo.FileName;
                    }
                    catch
                    {
                        current.ProcessPath = "";
                    }

                    try
                    {
                        current.IntegrityLevel = GetIntegerIntegrityLevel(GetIntegrityLevel(proc.Handle));
                    }
                    catch
                    {
                        current.IntegrityLevel = 0; // probably redundant
                    }

                    try
                    {
                        current.SessionId = proc.SessionId;
                    }
                    catch
                    {
                        current.SessionId = -1;
                    }

                    try
                    {
                        current.CommandLine = GetProcessCommandLine(proc.Id);
                    }
                    catch
                    {
                        current.CommandLine = "";
                    }

                    try
                    {
                        current.Description = proc.MainModule.FileVersionInfo.FileDescription;
                    }
                    catch
                    {
                        current.Description = "";
                    }

                    try
                    {
                        current.CompanyName = proc.MainModule.FileVersionInfo.CompanyName;
                        current.Signer = current.CompanyName;
                    }
                    catch
                    {
                        current.CompanyName = "";
                    }

                    try
                    {
                        current.WindowTitle = proc.MainWindowTitle;
                    }
                    catch
                    {
                        current.WindowTitle = "";
                    }

                    _processes.Add(current);
                });
            }
            catch (OperationCanceledException)
            {
            }

            _complete = true;
            _completed.Set();

            TaskResponse resp = CreateTaskResponse(
                "",
                true);
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif