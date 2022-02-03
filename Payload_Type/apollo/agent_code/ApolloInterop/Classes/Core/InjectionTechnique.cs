using ApolloInterop.Classes.Api;
using ApolloInterop.Interfaces;
using static ApolloInterop.Enums.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;

namespace ApolloInterop.Classes.Core
{
    public abstract class InjectionTechnique : IInjectionTechnique
    {
        protected byte[] _code;
        protected int _processId;
        protected IntPtr _hProcess = IntPtr.Zero;
        protected IAgent _agent;
        protected delegate IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int pid);
        protected delegate bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            ProcessAccessFlags dwDesiredAccess,
            bool bInheritHandle,
            int dwOptions);
        protected delegate void CloseHandle(IntPtr hHandle);

        protected OpenProcess _pOpenProcess;
        protected DuplicateHandle _pDuplicateHandle;
        protected CloseHandle _pCloseHandle;

        // Dangerous - should only be used when resolving
        // critical functions _pOpenProcess, _pDuplicateHandle,
        // and _pCloseHandle.
        public InjectionTechnique()
        {
            
        }
        public InjectionTechnique(IAgent agent, byte[] code, int pid)
        {
            _code = code;
            _processId = pid;
            _agent = agent;
            ResolveCriticalFunctions();
            _hProcess = _pOpenProcess(ProcessAccessFlags.MAXIMUM_ALLOWED, false, pid);
        }

        public InjectionTechnique(IAgent agent, byte[] code, IntPtr hProcess)
        {
            _code = code;
            _agent = agent;

            ResolveCriticalFunctions();
            bool bRet = _pDuplicateHandle(
                System.Diagnostics.Process.GetCurrentProcess().Handle,
                hProcess,
                hProcess,
                out _hProcess,
                ProcessAccessFlags.MAXIMUM_ALLOWED,
                false,
                0);
            if (!bRet)
            {
                throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
            }
        }

        ~InjectionTechnique()
        {
            if (_hProcess != IntPtr.Zero)
            {
                _pCloseHandle(_hProcess);
            }
        }

        private void ResolveCriticalFunctions()
        {
            _pOpenProcess = _agent.GetApi().GetLibraryFunction<OpenProcess>(Library.KERNEL32, "OpenProcess");
            _pDuplicateHandle = _agent.GetApi().GetLibraryFunction<DuplicateHandle>(Library.KERNEL32, "DuplicateHandle");
            _pCloseHandle = _agent.GetApi().GetLibraryFunction<CloseHandle>(Library.KERNEL32, "CloseHandle");
        }

        public abstract bool Inject(string arguments = "");
    }
}
