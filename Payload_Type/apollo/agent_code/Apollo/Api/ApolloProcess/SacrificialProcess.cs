using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using static ApolloInterop.Enums.Win32;
using static ApolloInterop.Structs.Win32;
using AI = ApolloInterop.Classes.Core;

namespace Apollo.Api.ApolloProcess
{
    public class SacrificialProcess : AI.Process
    {
        private SafeIntPtr _hParentProc = null;
        private ProcessInformation processInfo = new ProcessInformation();
        private StartupInfo startupInfo = new StartupInfo();
        private StartupInfoEx startupInfoEx = new StartupInfoEx();
        private CreateProcessFlags processFlags = CreateProcessFlags.CREATE_UNICODE_ENVIRONMENT;
        private SecurityAttributes securityAttributes = new SecurityAttributes();
        private readonly AutoResetEvent _exited = new AutoResetEvent(false);

        private TextReader _standardOutput;
        private TextReader _standardError;
        private TextReader _standardInput;

        private SafeFileHandle hReadOut, hWriteOut, hReadErr, hWriteErr, hReadIn, hWriteIn, hDupWriteOut = new SafeFileHandle(IntPtr.Zero, true), hDupWriteErr = new SafeFileHandle(IntPtr.Zero, true);
        private IntPtr unmanagedEnv;

        #region Delegate Typedefs
        // advapi32
        private delegate bool InitializeSecurityDescriptor(out SecurityDescriptor sd, uint dwRevision);
        private delegate bool SetSecurityDescriptorDacl(ref SecurityDescriptor sd, bool daclPresent, IntPtr dacl, bool daclDefaulted);
        // Kernel32
        private delegate bool CreatePipe(out SafeFileHandle phReadPipe, out SafeFileHandle phWritePipe, SecurityAttributes lpPipeAttributes, uint nSize);
        private delegate bool SetHandleInformation(SafeFileHandle hObject, int dwMask, uint dwFlags);
        private delegate IntPtr OpenProcess(
            ProcessAccessFlags dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId);
        private delegate bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);
        private delegate bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);
        private delegate bool DeleteProcThreadAttributeList(
            IntPtr lpAttributeList
        );
        private delegate bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            SafeFileHandle hSourceHandle,
            SafeFileHandle hTargetProcessHandle,
            ref SafeFileHandle lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            DuplicateOptions dwOptions
        );
        // Userenv.dll
        private delegate bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
        private delegate bool DestroyEnvironmentBlock(IntPtr lpEnvironment);



        #endregion

        public SacrificialProcess(
            IAgent agent,
            string lpApplication,
            string lpArguments = null,
            bool startSuspended = false) : base(agent, lpApplication, lpArguments, startSuspended)
        {
        }

        public override IEnumerable<string> GetOutput()
        {
            throw new NotImplementedException();
        }

        public override bool Inject(byte[] code, string arguments = "")
        {
            throw new NotImplementedException();
        }

        public override bool Start()
        {
            throw new NotImplementedException();
        }

        public override bool StartWithCredentials(ApolloLogonInformation logonInfo)
        {
            throw new NotImplementedException();
        }

        public override bool StartWithCredentials(SafeHandle hToken)
        {
            throw new NotImplementedException();
        }

        public override void WaitForExit()
        {
            throw new NotImplementedException();
        }

        public override void WaitForExit(int milliseconds)
        {
            throw new NotImplementedException();
        }
    }
}
