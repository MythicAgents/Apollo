#define COMMAND_NAME_UPPER

#if DEBUG
#define GETPRIVS
#endif

#if GETPRIVS

using ApolloInterop.Classes;
using ApolloInterop.Classes.Api;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class getprivs : Tasking
    {
        private static string[] _tokenPrivilegeNames = new string[] {
            "SeAssignPrimaryTokenPrivilege",
            "SeAuditPrivilege",
            "SeBackupPrivilege",
            "SeChangeNotifyPrivilege",
            "SeCreateGlobalPrivilege",
            "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege",
            "SeCreateSymbolicLinkPrivilege",
            "SeCreateTokenPrivilege",
            "SeDebugPrivilege",
            "SeDelegateSessionUserImpersonatePrivilege",
            "SeEnableDelegationPrivilege",
            "SeImpersonatePrivilege",
            "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeIncreaseWorkingSetPrivilege",
            "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege",
            "SeMachineAccountPrivilege",
            "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege",
            "SeRelabelPrivilege",
            "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege",
            "SeSecurityPrivilege",
            "SeShutdownPrivilege",
            "SeSyncAgentPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeSystemProfilePrivilege",
            "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeTcbPrivilege",
            "SeTimeZonePrivilege",
            "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege",
            "SeUnsolicitedInputPrivilege" };

        #region typedefs
        public enum ATTRIBUTES : UInt32
        {
            SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
            SE_PRIVILEGE_ENABLED = 0x00000002,
            SE_PRIVILEGE_REMOVED = 0x00000004,
            SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public ATTRIBUTES Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;

            public LUID(UInt64 value)
            {
                LowPart = (UInt32)(value & 0xffffffffL);
                HighPart = (Int32)(value >> 32);
            }

            public LUID(LUID value)
            {
                LowPart = value.LowPart;
                HighPart = value.HighPart;
            }

            public LUID(string value)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(value, @"^0x[0-9A-Fa-f]+$"))
                {
                    // if the passed LUID string is of form 0xABC123
                    UInt64 uintVal = Convert.ToUInt64(value, 16);
                    LowPart = (UInt32)(uintVal & 0xffffffffL);
                    HighPart = (Int32)(uintVal >> 32);
                }
                else if (System.Text.RegularExpressions.Regex.IsMatch(value, @"^\d+$"))
                {
                    // if the passed LUID string is a decimal form
                    UInt64 uintVal = UInt64.Parse(value);
                    LowPart = (UInt32)(uintVal & 0xffffffffL);
                    HighPart = (Int32)(uintVal >> 32);
                }
                else
                {
                    ArgumentException argEx = new ArgumentException("Passed LUID string value is not in a hex or decimal form", value);
                    throw argEx;
                }
            }

            public override int GetHashCode()
            {
                UInt64 Value = ((UInt64)this.HighPart << 32) + this.LowPart;
                return Value.GetHashCode();
            }

            public override bool Equals(object obj)
            {
                return obj is LUID && (((ulong)this) == (LUID)obj);
            }

            public byte[] GetBytes()
            {
                byte[] bytes = new byte[8];

                byte[] lowBytes = BitConverter.GetBytes(this.LowPart);
                byte[] highBytes = BitConverter.GetBytes(this.HighPart);

                Array.Copy(lowBytes, 0, bytes, 0, 4);
                Array.Copy(highBytes, 0, bytes, 4, 4);

                return bytes;
            }

            public override string ToString()
            {
                UInt64 Value = ((UInt64)this.HighPart << 32) + this.LowPart;
                return String.Format("0x{0:x}", (ulong)Value);
            }

            public static bool operator ==(LUID x, LUID y)
            {
                return (((ulong)x) == ((ulong)y));
            }

            public static bool operator !=(LUID x, LUID y)
            {
                return (((ulong)x) != ((ulong)y));
            }

            public static implicit operator ulong(LUID luid)
            {
                // enable casting to a ulong
                UInt64 Value = ((UInt64)luid.HighPart << 32);
                return Value + luid.LowPart;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TokenPrivileges
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
            //public LUID_AND_ATTRIBUTES Privileges;

            //public TOKEN_PRIVILEGES(uint PrivilegeCount, LUID_AND_ATTRIBUTES Privileges)
            //{
            //    this.PrivilegeCount = PrivilegeCount;
            //    this.Privileges = Privileges;
            //}
        }

        private delegate bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
        private delegate bool AdjustTokenPrivileges(IntPtr hToken, bool bDisableAllPrivileges, ref TokenPrivileges lpNewState, int dwBufferLength, IntPtr null1, IntPtr null2);

        private LookupPrivilegeValue _pLookupPrivilegeValue;
        private AdjustTokenPrivileges _pAdjustTokenPrivileges;
        
        #endregion
        public getprivs(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
            _pLookupPrivilegeValue = _agent.GetApi().GetLibraryFunction<LookupPrivilegeValue>(Library.ADVAPI32, "LookupPrivilegeValueA");
            _pAdjustTokenPrivileges = _agent.GetApi().GetLibraryFunction<AdjustTokenPrivileges>(Library.ADVAPI32, "AdjustTokenPrivileges");
        }

        private bool SePrivEnable(IntPtr hToken, string priv)
        {
            bool bRet = false;
            //_LUID lpLuid = new _LUID();
            var tokenPrivileges = new TokenPrivileges();
            tokenPrivileges.Privileges = new LUID_AND_ATTRIBUTES[1];
            bRet = _pLookupPrivilegeValue(null, priv, out tokenPrivileges.Privileges[0].Luid);
            if (!bRet)
                return bRet;
            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Privileges[0].Attributes = ATTRIBUTES.SE_PRIVILEGE_ENABLED;
            _pAdjustTokenPrivileges(hToken, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
            if (Marshal.GetLastWin32Error() == 0)
                bRet = true;
            else
                bRet = false;
            return bRet;
        }

        public override void Start()
        {
            TaskResponse resp;
            WindowsIdentity impersonationIdentity = _agent.GetIdentityManager().GetCurrentImpersonationIdentity();
            WindowsIdentity primaryIdentity = _agent.GetIdentityManager().GetCurrentPrimaryIdentity();
            List<string> imperonationPrivs = new List<string>();
            List<string> primaryPrivs = new List<string>();
            foreach (string name in _tokenPrivilegeNames)
            {
                if (SePrivEnable(impersonationIdentity.Token, name))
                {
                    imperonationPrivs.Add(name);
                }

                if (SePrivEnable(primaryIdentity.Token, name))
                {
                    primaryPrivs.Add(name);
                }
            }

            resp = CreateTaskResponse("Impersonation identity enabled privileges:\n" + 
                                      string.Join("\n", imperonationPrivs.ToArray()) + "\n\n" +
                                      "Primary identity enabled privileges:\n" +
                                      string.Join("\n", primaryPrivs.ToArray()), true, "completed");
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif