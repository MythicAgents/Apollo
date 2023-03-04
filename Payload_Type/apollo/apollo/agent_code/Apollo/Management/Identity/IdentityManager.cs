using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using ApolloInterop.Classes.Api;
using static ApolloInterop.Enums.Win32;
using static ApolloInterop.Constants.Win32;
using System.Runtime.InteropServices;
using static ApolloInterop.Structs.Win32;
using ApolloInterop.Structs.MythicStructs;
using System.Security;

namespace Apollo.Management.Identity
{
    public class IdentityManager : IIdentityManager
    {
        private IAgent _agent;

        private ApolloLogonInformation _userCredential;
        private WindowsIdentity _originalIdentity = WindowsIdentity.GetCurrent();
        private WindowsIdentity _currentPrimaryIdentity = WindowsIdentity.GetCurrent();
        private WindowsIdentity _currentImpersonationIdentity = WindowsIdentity.GetCurrent();
        private bool _isImpersonating = false;
        
        private IntPtr _executingThread = IntPtr.Zero;
        private IntPtr _originalImpersonationToken = IntPtr.Zero;
        private IntPtr _originalPrimaryToken = IntPtr.Zero;

        #region Delegate Typedefs
        private delegate IntPtr GetCurrentThread();
        private delegate bool OpenThreadToken(
            IntPtr threadHandle,
            uint desiredAccess,
            bool openAsSelf,
            out IntPtr tokenHandle);
        private delegate bool OpenProcessToken(
            IntPtr hProcess,
            uint dwDesiredAccess,
            out IntPtr hToken);
        private delegate bool DuplicateTokenEx(
            IntPtr hToken,
            TokenAccessLevels dwDesiredAccess,
            IntPtr lpTokenAttributes,
            TokenImpersonationLevel impersonationLevel,
            TokenType tokenType,
            out IntPtr phNewToken);
        private delegate bool SetThreadToken(
            ref IntPtr hThread,
            IntPtr hToken);
        private delegate bool CloseHandle(
            IntPtr hHandle);
        private delegate bool GetTokenInformation(
            IntPtr tokenHandle,
            TokenInformationClass tokenInformationClass,
            IntPtr tokenInformation,
            int tokenInformationLength,
            out int returnLength);
        private delegate IntPtr GetSidSubAuthorityCount(IntPtr pSid);
        private delegate IntPtr GetSidSubAuthority(IntPtr pSid, int nSubAuthority);
        private delegate bool LogonUserA(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            LogonType dwLogonType,
            LogonProvider dwLogonProvider,
            out IntPtr phToken);

        private GetCurrentThread _GetCurrentThread;
        private OpenThreadToken _OpenThreadToken;
        private OpenProcessToken _OpenProcessToken;
        private DuplicateTokenEx _DuplicateTokenEx;
        private SetThreadToken _SetThreadToken;
        private CloseHandle _CloseHandle;
        private GetTokenInformation _GetTokenInformation;
        private GetSidSubAuthorityCount _GetSidSubAuthorityCount;
        private GetSidSubAuthority _GetSidSubAuthority;
        private LogonUserA _pLogonUserA;
        #endregion
        public IdentityManager(IAgent agent)
        {
            _agent = agent;

            _GetCurrentThread = _agent.GetApi().GetLibraryFunction<GetCurrentThread>(Library.KERNEL32, "GetCurrentThread");
            _OpenThreadToken = _agent.GetApi().GetLibraryFunction<OpenThreadToken>(Library.ADVAPI32, "OpenThreadToken");
            _OpenProcessToken = _agent.GetApi().GetLibraryFunction<OpenProcessToken>(Library.ADVAPI32, "OpenProcessToken");
            _DuplicateTokenEx = _agent.GetApi().GetLibraryFunction<DuplicateTokenEx>(Library.ADVAPI32, "DuplicateTokenEx");
            _SetThreadToken = _agent.GetApi().GetLibraryFunction<SetThreadToken>(Library.ADVAPI32, "SetThreadToken");
            _CloseHandle = _agent.GetApi().GetLibraryFunction<CloseHandle>(Library.KERNEL32, "CloseHandle");
            _GetTokenInformation = _agent.GetApi().GetLibraryFunction<GetTokenInformation>(Library.ADVAPI32, "GetTokenInformation");
            _GetSidSubAuthorityCount = _agent.GetApi().GetLibraryFunction<GetSidSubAuthorityCount>(Library.ADVAPI32, "GetSidSubAuthorityCount");
            _GetSidSubAuthority = _agent.GetApi().GetLibraryFunction<GetSidSubAuthority>(Library.ADVAPI32, "GetSidSubAuthority");
            _pLogonUserA = _agent.GetApi().GetLibraryFunction<LogonUserA>(Library.ADVAPI32, "LogonUserA");

            _executingThread = _GetCurrentThread();
            SetImpersonationToken();
            SetPrimaryToken();
        }

        private void SetPrimaryToken()
        {
            bool bRet = _OpenThreadToken(
                _executingThread,
                TOKEN_ALL_ACCESS,
                true,
                out _originalPrimaryToken);
            int dwError = Marshal.GetLastWin32Error();
            if (!bRet && Error.ERROR_NO_TOKEN == dwError)
            {
                IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;
                bRet = _OpenProcessToken(
                    hProcess,
                    TOKEN_ALL_ACCESS,
                    out _originalPrimaryToken);
            }
            else if (!bRet)
            {
                throw new Exception($"Failed to open thread token: {dwError}");
            }
            else
            {
                throw new Exception($"Failed to open thread token and have unhandled error. dwError: {dwError}");
            }
            if (_originalPrimaryToken == IntPtr.Zero)
                _originalPrimaryToken = WindowsIdentity.GetCurrent().Token;
        }

        public bool IsOriginalIdentity()
        {
            return !_isImpersonating;
        }

        public IntegrityLevel GetIntegrityLevel()
        {
            IntPtr hToken = _currentImpersonationIdentity.Token;
            int dwRet = 0;
            bool bRet = false;
            int dwTokenInfoLength = 0;
            IntPtr pTokenInformation = IntPtr.Zero;
            TokenMandatoryLevel tokenLabel;
            IntPtr pTokenLabel = IntPtr.Zero;
            IntPtr pSidSubAthorityCount = IntPtr.Zero;
            bRet = _GetTokenInformation(
                hToken,
                TokenInformationClass.TokenIntegrityLevel,
                IntPtr.Zero,
                0,
                out dwTokenInfoLength);
            if (dwTokenInfoLength == 0 || Marshal.GetLastWin32Error() != Error.ERROR_INSUFFICIENT_BUFFER)
                return (IntegrityLevel)dwRet;
            pTokenLabel = Marshal.AllocHGlobal(dwTokenInfoLength);
            try
            {
                bRet = _GetTokenInformation(
                    hToken,
                    TokenInformationClass.TokenIntegrityLevel,
                    pTokenLabel,
                    dwTokenInfoLength,
                    out dwTokenInfoLength);
                if (bRet)
                {
                    tokenLabel = (TokenMandatoryLevel)Marshal.PtrToStructure(pTokenLabel, typeof(TokenMandatoryLevel));
                    pSidSubAthorityCount = _GetSidSubAuthorityCount(tokenLabel.Label.Sid);
                    dwRet = Marshal.ReadInt32(_GetSidSubAuthority(tokenLabel.Label.Sid, Marshal.ReadInt32(pSidSubAthorityCount) - 1));
                    if (dwRet < SECURITY_MANDATORY_LOW_RID)
                        dwRet = 0;
                    else if (dwRet < SECURITY_MANDATORY_MEDIUM_RID)
                        dwRet = 1;
                    else if (dwRet >= SECURITY_MANDATORY_MEDIUM_RID && dwRet < SECURITY_MANDATORY_HIGH_RID)
                        dwRet = 2;
                    else if (dwRet >= SECURITY_MANDATORY_HIGH_RID && dwRet < SECURITY_MANDATORY_SYSTEM_RID)
                        dwRet = 3;
                    else if (dwRet >= SECURITY_MANDATORY_SYSTEM_RID)
                        dwRet = 4;
                    else
                        dwRet = 0; // unknown - should be unreachable.

                }
            }
            catch (Exception ex)
            { }
            finally
            {
                Marshal.FreeHGlobal(pTokenLabel);
            }
            return (IntegrityLevel)dwRet;
        }

        private void SetImpersonationToken()
        {
            bool bRet = _OpenThreadToken(
                            _executingThread,
                            TOKEN_ALL_ACCESS,
                            true,
                            out IntPtr hToken);
            int dwError = Marshal.GetLastWin32Error();
            if (!bRet && Error.ERROR_NO_TOKEN == dwError)
            {
                IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;
                bRet = _OpenProcessToken(
                    hProcess,
                    TOKEN_ALL_ACCESS,
                    out hToken);
                if (!bRet)
                {
                    throw new Exception($"Failed to acquire Process token: {Marshal.GetLastWin32Error()}");
                }
                bRet = _DuplicateTokenEx(
                    hToken,
                    TokenAccessLevels.MaximumAllowed,
                    IntPtr.Zero,
                    TokenImpersonationLevel.Impersonation,
                    TokenType.TokenImpersonation,
                    out _originalImpersonationToken);

                if (!bRet)
                {
                    throw new Exception($"Failed to acquire Process token: {Marshal.GetLastWin32Error()}");
                }
            }
            else if (!bRet)
            {
                throw new Exception($"Failed to open thread token: {dwError}");
            }

            if (_originalImpersonationToken == IntPtr.Zero)
            {
                _originalImpersonationToken = _originalIdentity.Token;
            }
        }

        public WindowsIdentity GetCurrent()
        {
            return _currentImpersonationIdentity;
        }

        public WindowsIdentity GetOriginal()
        {
            return _originalIdentity;
        }

        public bool SetIdentity(ApolloLogonInformation logonInfo)
        {
            bool bRet = false;
            int dwError = 0;
            IntPtr hToken = IntPtr.Zero;

            Revert();
            // Blank out the old struct
            _userCredential = logonInfo;

            bRet = _pLogonUserA(
                _userCredential.Username,
                _userCredential.Domain,
                _userCredential.Password,
                LogonType.LOGON32_LOGON_NEW_CREDENTIALS,
                LogonProvider.LOGON32_PROVIDER_WINNT50,
                out hToken);

            if (bRet)
            {
                _currentPrimaryIdentity = new WindowsIdentity(hToken);
                _CloseHandle(hToken);
                bRet = _DuplicateTokenEx(
                    _currentPrimaryIdentity.Token,
                    TokenAccessLevels.MaximumAllowed,
                    IntPtr.Zero,
                    TokenImpersonationLevel.Impersonation,
                    TokenType.TokenImpersonation,
                    out IntPtr dupToken);
                if (bRet)
                {
                    _currentImpersonationIdentity = new WindowsIdentity(dupToken);
                    _CloseHandle(dupToken);
                    _isImpersonating = true;
                }
                else
                {
                    Revert();
                }
            }
            return bRet;
        }

        public void SetPrimaryIdentity(WindowsIdentity ident)
        {
            _currentPrimaryIdentity = ident;
            _isImpersonating = true;
        }

        public void SetPrimaryIdentity(IntPtr hToken)
        {
            _currentPrimaryIdentity = new WindowsIdentity(hToken);
            _isImpersonating = true;
        }

        public void SetImpersonationIdentity(WindowsIdentity ident)
        {
            _currentImpersonationIdentity = ident;
            _isImpersonating = true;
        }

        public void SetImpersonationIdentity(IntPtr hToken)
        {
            _currentImpersonationIdentity = new WindowsIdentity(hToken);
            _isImpersonating = true;
        }

        public void Revert()
        {
            _SetThreadToken(ref _executingThread, _originalImpersonationToken);
            _userCredential = new ApolloLogonInformation();
            _currentImpersonationIdentity = _originalIdentity;
            _currentPrimaryIdentity = _originalIdentity;
            _isImpersonating = false;
        }

        public WindowsIdentity GetCurrentPrimaryIdentity()
        {
            return _currentPrimaryIdentity;
        }

        public WindowsIdentity GetCurrentImpersonationIdentity()
        {
            return _currentImpersonationIdentity;
        }

        public bool GetCurrentLogonInformation(out ApolloLogonInformation logonInfo)
        {
            if (!string.IsNullOrEmpty(_userCredential.Username) &&
                !string.IsNullOrEmpty(_userCredential.Password))
            {
                logonInfo = _userCredential;
                return true;
            }
            logonInfo = new ApolloLogonInformation();
            return false;
        }
    }
}
