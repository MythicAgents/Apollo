using System;
using System.Security.Principal;
//using static Native.Enums;

namespace Native
{
    internal static class Constants
    {
        #region CONSTANTS
        public const long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;
        public const int HANDLE_FLAG_INHERIT = 1;
        public static uint STARTF_USESTDHANDLES = 0x00000100;
        public const UInt32 INFINITE = 0xFFFFFFFF;
        public const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;

        internal const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        internal const uint TOKEN_ALL_ACCESS_P = (STANDARD_RIGHTS_REQUIRED |
                          (uint)TokenAccessLevels.AssignPrimary |
                          (uint)TokenAccessLevels.Duplicate |
                          (uint)TokenAccessLevels.Impersonate|
                          (uint)TokenAccessLevels.Query |
                          (uint)TokenAccessLevels.QuerySource |
                          (uint)TokenAccessLevels.AdjustPrivileges|
                          (uint)TokenAccessLevels.AdjustGroups |
                          (uint)TokenAccessLevels.AdjustDefault);

        internal const uint TOKEN_ALL_ACCESS = TOKEN_ALL_ACCESS_P | (uint)TokenAccessLevels.AdjustSessionId;
        internal static string[] TokenPrivilegeNames = new string[] { "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeDelegateSessionUserImpersonatePrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege", "SeUnsolicitedInputPrivilege" };

        public const int DUPLICATE_CLOSE_SOURCE = 0x00000001;
        public const int DUPLICATE_SAME_ACCESS = 0x00000002;
        public const int INVALID_HANDLE_VALUE = -1;
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint GENERIC_EXECUTE = 0x20000000;
        public const uint GENERIC_ALL = 0x10000000;

        public const uint FILE_SHARE_DELETE = 0x00000004;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;

        public const uint SECURITY_MANDATORY_LOW_RID = 0x00001000;
        public const uint SECURITY_MANDATORY_MEDIUM_RID = 0x00002000;
        public const uint SECURITY_MANDATORY_HIGH_RID = 0x00003000;
        public const uint SECURITY_MANDATORY_SYSTEM_RID = 0x00004000;

        public const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
        public const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
        #endregion

    }
}
