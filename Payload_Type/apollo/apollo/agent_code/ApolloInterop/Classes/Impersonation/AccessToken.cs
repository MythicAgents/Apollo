using ApolloInterop.Structs;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using static ApolloInterop.Constants.Win32;
using static ApolloInterop.Enums.Win32;
using static ApolloInterop.Features.WindowsTypesAndAPIs.APIInteropTypes;
using static ApolloInterop.Features.WindowsTypesAndAPIs.WinNTTypes;
using static ApolloInterop.Structs.Win32;

namespace ApolloInterop.Classes.Impersonation
{
    public sealed class AccessToken : IDisposable
    {
        public SafeTokenHandle TokenHandle { get; }
        public ApolloLogonInformation? SourceCredentials { get; }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public PrivilegeAttributes Attributes;
        }

        public bool IsNetworkOnly => GetTokenSource() == "Seclogo";

        public bool CanImpersonate => !IsNetworkOnly &&
            HasPrivilege(TokenPrivilege.SeImpersonatePrivilege, requireEnabled: true);

        public AccessToken(SafeTokenHandle handle)
            : this(handle, null)
        {

        }

        public AccessToken(SafeTokenHandle handle, ApolloLogonInformation? creds)
        {
            TokenHandle = handle ?? throw new ArgumentNullException(nameof(handle));

            if (TokenHandle.IsInvalid)
                throw new ArgumentException("Invalid token handle.", nameof(handle));

            SourceCredentials = creds;
        }

        public void Dispose()
        {
            TokenHandle?.Dispose();
        }

        public string GetUserPrincipalName()
        {
            IntPtr info = IntPtr.Zero;
            int length = 0;

            try
            {
                GetTokenInformation(TokenHandle,
                                    TokenInformationClass.TokenUser,
                                    IntPtr.Zero,
                                    0,
                                    out length);

                if (length == 0)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                info = Marshal.AllocHGlobal(length);

                if (!GetTokenInformation(TokenHandle,
                                         TokenInformationClass.TokenUser,
                                         info,
                                         length,
                                         out length))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                TOKEN_USER tu = (TOKEN_USER)Marshal.PtrToStructure(info, typeof(TOKEN_USER));

                StringBuilder name = new StringBuilder(256);
                StringBuilder domain = new StringBuilder(256);
                int nameLen = name.Capacity;
                int domainLen = domain.Capacity;
                int peUse;

                if (!LookupAccountSid(null,
                                      tu.User.Sid,
                                      name,
                                      ref nameLen,
                                      domain,
                                      ref domainLen,
                                      out peUse))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                return domain.Length > 0 ? $"{domain}\\{name}" : name.ToString();
            }
            finally
            {
                if (info != IntPtr.Zero)
                    Marshal.FreeHGlobal(info);
            }
        }

        private string GetTokenSource()
        {
            IntPtr info = IntPtr.Zero;
            int length = 0;

            try
            {
                GetTokenInformation(TokenHandle,
                                    TokenInformationClass.TokenSource,
                                    IntPtr.Zero,
                                    0,
                                    out length);

                if (length == 0)
                    return string.Empty;

                info = Marshal.AllocHGlobal(length);

                if (!GetTokenInformation(TokenHandle,
                                         TokenInformationClass.TokenSource,
                                         info,
                                         length,
                                         out length))
                    return string.Empty;

                TOKEN_SOURCE src = (TOKEN_SOURCE)Marshal.PtrToStructure(
                    info, typeof(TOKEN_SOURCE));

                if (src.SourceName == null)
                    return string.Empty;

                return Encoding.UTF8.GetString(src.SourceName).TrimEnd('\0');
            }
            finally
            {
                if (info != IntPtr.Zero)
                    Marshal.FreeHGlobal(info);
            }
        }

        private string LookupPrivilegeName(LUID luid)
        {
            int len = 0;
            LookupPrivilegeNameW(null, ref luid, null, ref len);

            var sb = new StringBuilder(len + 1);

            if (LookupPrivilegeNameW(null, ref luid, sb, ref len))
                return sb.ToString();

            return string.Empty;
        }

        private IEnumerable<(string Name, PrivilegeAttributes Attributes)> EnumerateRawPrivileges()
        {
            IntPtr info = IntPtr.Zero;
            int length = 0;

            try
            {
                GetTokenInformation(
                    TokenHandle,
                    TokenInformationClass.TokenPrivileges,
                    IntPtr.Zero,
                    0,
                    out length);

                if (length == 0)
                    yield break;

                info = Marshal.AllocHGlobal(length);

                if (!GetTokenInformation(
                        TokenHandle,
                        TokenInformationClass.TokenPrivileges,
                        info,
                        length,
                        out length))
                    yield break;

                uint count = (uint)Marshal.ReadInt32(info);
                IntPtr ptr = new IntPtr(info.ToInt64() + sizeof(uint));

                for (int i = 0; i < count; i++)
                {
                    var la = Marshal.PtrToStructure<LUID_AND_ATTRIBUTES>(ptr);
                    string name = LookupPrivilegeName(la.Luid);
                    yield return (name, la.Attributes);

                    ptr = new IntPtr(ptr.ToInt64() + Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES)));
                }
            }
            finally
            {
                if (info != IntPtr.Zero)
                    Marshal.FreeHGlobal(info);
            }
        }

        public bool HasPrivilege(TokenPrivilege privilege, bool requireEnabled = true)
        {
            string target = privilege.ToString();

            foreach (var (name, attrs) in EnumerateRawPrivileges())
            {
                if (string.Equals(name, target, StringComparison.OrdinalIgnoreCase))
                {
                    if (!requireEnabled)
                        return true;

                    return (attrs & PrivilegeAttributes.SE_PRIVILEGE_ENABLED) != 0;
                }
            }

            return false;
        }

        public IEnumerable<(TokenPrivilege Privilege, bool Enabled)> EnumeratePrivileges()
        {
            foreach (var (name, attrs) in EnumerateRawPrivileges())
            {
                bool enabled = (attrs & PrivilegeAttributes.SE_PRIVILEGE_ENABLED) != 0;

                if (Enum.TryParse(name, ignoreCase: true, out TokenPrivilege parsed))
                {
                    yield return (parsed, enabled);
                }
                else
                {
                    yield return (TokenPrivilege.Unknown, enabled);
                }
            }
        }

        public AccessToken Duplicate(
            TokenType tokenType = TokenType.TokenImpersonation,
            TokenAccessLevels access = TokenAccessLevels.MaximumAllowed,
            TokenImpersonationLevel level = TokenImpersonationLevel.Impersonation)
        {
            var result = DuplicateTokenEx(
                TokenHandle,
                access,
                IntPtr.Zero,
                level,
                tokenType,
                out SafeTokenHandle dup
            );

            if (!result)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return new AccessToken(dup);
        }

        public IntegrityLevel GetIntegrityLevel()
        {
            int length = 0;

            GetTokenInformation(
                TokenHandle,
                TokenInformationClass.TokenIntegrityLevel,
                IntPtr.Zero,
                0,
                out length
            );

            if (length == 0 && Marshal.GetLastWin32Error() != Error.ERROR_INSUFFICIENT_BUFFER)
                return 0;

            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!GetTokenInformation(
                        TokenHandle,
                        TokenInformationClass.TokenIntegrityLevel,
                        buffer,
                        length,
                        out length))
                    return 0;

                var tml = Marshal.PtrToStructure<TokenMandatoryLevel>(buffer);
                IntPtr pCount = GetSidSubAuthorityCount(tml.Label.Sid);
                int subAuthCount = Marshal.ReadByte(pCount);
                IntPtr pRid = GetSidSubAuthority(tml.Label.Sid, subAuthCount - 1);
                int rid = Marshal.ReadInt32(pRid);

                if (rid < SECURITY_MANDATORY_LOW_RID)
                    return 0;
                else if (rid < SECURITY_MANDATORY_MEDIUM_RID)
                    return (IntegrityLevel)1;
                else if (rid >= SECURITY_MANDATORY_MEDIUM_RID && rid < SECURITY_MANDATORY_HIGH_RID)
                    return (IntegrityLevel)2;
                else if (rid >= SECURITY_MANDATORY_HIGH_RID && rid < SECURITY_MANDATORY_SYSTEM_RID)
                    return (IntegrityLevel)3;
                else if (rid >= SECURITY_MANDATORY_SYSTEM_RID)
                    return (IntegrityLevel)4;

                return 0;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public override string ToString()
        {
            string user = GetUserPrincipalName();
            IntegrityLevel il = GetIntegrityLevel();

            return $"User: {user}, IL: {il}, NetOnly: {IsNetworkOnly}, CanImpersonate: {CanImpersonate}";
        }

        public static AccessToken FromCurrentProcess()
        {
            IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;

            if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, out SafeTokenHandle hTok))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return new AccessToken(hTok);
        }

        public static AccessToken FromCurrentThreadOrProcess()
        {
            if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, true, out SafeTokenHandle hTok))
                return new AccessToken(hTok);

            int err = Marshal.GetLastWin32Error();

            if (err != Error.ERROR_NO_TOKEN)
                throw new Win32Exception(err);

            return FromCurrentProcess();
        }

        public static AccessToken FromLogonUser(ApolloLogonInformation info)
        {
            if (!LogonUserW(
                    info.Username,
                    info.Domain,
                    info.Password,
                    info.NetOnly ? LogonType.LOGON32_LOGON_NEW_CREDENTIALS : LogonType.LOGON32_LOGON_INTERACTIVE,
                    LogonProvider.LOGON32_PROVIDER_WINNT50,
                    out SafeTokenHandle hTok))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return new AccessToken(hTok, info);
        }

        public static AccessToken FromSystemByProcessName(string processName = "winlogon")
        {
            var procs = System.Diagnostics.Process.GetProcessesByName(processName);

            if (procs.Length == 0)
                throw new InvalidOperationException($"{processName} not found.");

            IntPtr hProcess = procs[0].Handle;

            if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, out SafeTokenHandle hTok))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            using var baseTok = new AccessToken(hTok);

            return baseTok.Duplicate(
                tokenType: TokenType.TokenImpersonation,
                access: TokenAccessLevels.MaximumAllowed,
                level: TokenImpersonationLevel.Impersonation
            );
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupAccountSid(
           string lpSystemName,
           IntPtr Sid,
           StringBuilder Name,
           ref int cchName,
           StringBuilder ReferencedDomainName,
           ref int cchReferencedDomainName,
           out int peUse);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupPrivilegeNameW(
            string? lpSystemName,
            ref LUID lpLuid,
            StringBuilder? lpName,
            ref int cchName
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenThreadToken(
            IntPtr ThreadHandle,
            uint DesiredAccess,
            bool OpenAsSelf,
            out SafeTokenHandle TokenHandle
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out SafeTokenHandle TokenHandle
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(
            SafeTokenHandle hExistingToken,
            TokenAccessLevels dwDesiredAccess,
            IntPtr lpTokenAttributes,
            TokenImpersonationLevel ImpersonationLevel,
            TokenType TokenType,
            out SafeTokenHandle phNewToken
        );

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            SafeTokenHandle TokenHandle,
            TokenInformationClass TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr pSid, int nSubAuthority);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUserW(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            LogonType dwLogonType,
            LogonProvider dwLogonProvider,
            out SafeTokenHandle phToken
        );

        private const uint TOKEN_ALL_ACCESS = 0xF01FF;
    }
}
