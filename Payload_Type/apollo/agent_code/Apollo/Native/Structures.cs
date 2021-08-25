using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using static Native.Enums;

namespace Native
{
    internal static class Structures
    {


        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct SECURITY_DESCRIPTOR
        {
            public byte revision;
            public byte size;
            public short control;
            public IntPtr owner;
            public IntPtr group;
            public IntPtr sacl;
            public IntPtr dacl;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct StartupInfo
        {
            public Int32 cb;
            public String lpReserved;
            public String lpDesktop;

            public String lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public STARTF dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public SafeFileHandle hStdInput;
            public SafeFileHandle hStdOutput;
            public SafeFileHandle hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SecurityAttributes
        {
            public Int32 nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;

            public SecurityAttributes()
            {
                this.nLength = Marshal.SizeOf(this);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct STARTUPINFO
        {
            internal Int32 cb;
            internal IntPtr lpReserved;
            internal IntPtr lpDesktop;
            internal IntPtr lpTitle;
            internal Int32 dwX;
            internal Int32 dwY;
            internal Int32 dwXSize;
            internal Int32 dwYSize;
            internal Int32 dwXCountChars;
            internal Int32 dwYCountChars;
            internal Int32 dwFillAttribute;
            internal STARTF dwFlags;
            internal Int16 wShowWindow;
            internal Int16 cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }



        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public int Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_ENUMERATION_INFORMATION
        {
            public IntPtr PSid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SC_SERVICE_TAG_QUERY
        {
            public uint ProcessId;
            public uint ServiceTag;
            public uint Unknown;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct TOKEN_STATISTICS
        {
            public LUID TokenId;
            public LUID AuthenticationId;
            public long ExpirationTime;
            public uint TokenType;
            public uint ImpersonationLevel;
            public uint DynamicCharged;
            public uint DynamicAvailable;
            public uint GroupCount;
            public uint PrivilegeCount;
            public LUID ModifiedId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 dwProcessId;
            public Int32 dwThreadId;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct CREDENTIAL
        {
            public int Flags;
            public CredentialType Type;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
            [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
            public long LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public PersistenceType Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
            [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_IN
        {
            public ushort Length;
            public ushort MaximumLength;
            public string Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_OUT
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_LOGON_SESSION_DATA
        {
            public uint Size;
            public LUID LoginID;
            public LSA_STRING_OUT Username;
            public LSA_STRING_OUT LoginDomain;
            public LSA_STRING_OUT AuthenticationPackage;
            public uint LogonType;
            public uint Session;
            public IntPtr PSiD;
            public ulong LoginTime;
            public LSA_STRING_OUT LogonServer;
            public LSA_STRING_OUT DnsDomainName;
            public LSA_STRING_OUT Upn;
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
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_GROUPS
        {
            public int GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public SID_AND_ATTRIBUTES[] Groups;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_MANDATORY_LEVEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
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

        // This also works with CharSet.Ansi as long as the calling function uses the same character set.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct StartupInfoEx
        {
            public StartupInfo StartupInfo;
            public IntPtr lpAttributeList;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }


        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            internal IntPtr ExitStatus;
            internal IntPtr PebBaseAddress;
            internal IntPtr AffinityMask;
            internal IntPtr BasePriority;
            internal UIntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public _LUID_AND_ATTRIBUTES Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _LUID_AND_ATTRIBUTES
        {
            public _LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _LUID
        {
            public UInt32 LowPart;
            public UInt32 HighPart;
        }


        /// <summary>
        /// This structure contains information about a file object.
        /// </summary>
        /// <remarks>
        /// This structure is used with the SHGetFileInfo function.
        /// </remarks>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct SHFILEINFO
        {
            /// <summary>
            /// Handle to the icon that represents the file. 
            /// </summary>
            internal IntPtr hIcon;

            /// <summary>
            /// Index of the icon image within the system image list.
            /// </summary>
            internal int iIcon;

            /// <summary>
            /// Specifies the attributes of the file object.
            /// </summary>
            internal uint dwAttributes;

            /// <summary>
            /// Null-terminated string that contains the name of the file as it 
            /// appears in the Windows shell, or the path and name of the file that
            /// contains the icon representing the file.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            internal string szDisplayName;

            /// <summary>
            /// Null-terminated string that describes the type of file. 
            /// </summary>
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
            internal string szTypeName;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SERVICE_STATUS
        {
            public static readonly int SizeOf = Marshal.SizeOf(typeof(SERVICE_STATUS));

            public SERVICE_TYPES dwServiceType;

            public SERVICE_STATE dwCurrentState;

            public uint dwControlsAccepted;

            public uint dwWin32ExitCode;

            public uint dwServiceSpecificExitCode;

            public uint dwCheckPoint;

            public uint dwWaitHint;
        }

        /*
         * typedef struct _LOCALGROUP_MEMBERS_INFO_0 {
  PSID lgrmi0_sid;
} LOCALGROUP_MEMBERS_INFO_0, *PLOCALGROUP_MEMBERS_INFO_0, *LPLOCALGROUP_MEMBERS_INFO_0;
*/
        [StructLayout(LayoutKind.Sequential)]
        public struct LOCALGROUP_MEMBERS_INFO_0
        {
            // Pointer to a SID structure that contains the security identifier (SID) of the local group member.
            public IntPtr lgrmi0_sid;
        }

        /*
         * typedef struct _LOCALGROUP_MEMBERS_INFO_1 {
  PSID         lgrmi1_sid;
  SID_NAME_USE lgrmi1_sidusage;
  LPWSTR       lgrmi1_name;
} LOCALGROUP_MEMBERS_INFO_1, *PLOCALGROUP_MEMBERS_INFO_1, *LPLOCALGROUP_MEMBERS_INFO_1;
*/
        [StructLayout(LayoutKind.Sequential)]
        public struct LOCALGROUP_MEMBERS_INFO_1
        {
            public IntPtr lgrmi1_sid;
            public SID_NAME_USE lgrmi1_sidusage;
            string lgrmi1_name;
        }

        /*
         * typedef struct _LOCALGROUP_MEMBERS_INFO_2 {
  PSID         lgrmi2_sid;
  SID_NAME_USE lgrmi2_sidusage;
  LPWSTR       lgrmi2_domainandname;
} LOCALGROUP_MEMBERS_INFO_2, *PLOCALGROUP_MEMBERS_INFO_2, *LPLOCALGROUP_MEMBERS_INFO_2;
*/
        [StructLayout(LayoutKind.Sequential)]
        public struct LOCALGROUP_MEMBERS_INFO_2
        {
            public IntPtr lgrmi2_sid;
            public SID_NAME_USE lgrmi2_sidusage;
            public IntPtr lgrmi2_domainandname;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_USERS_INFO_0
        {
            [MarshalAs(UnmanagedType.LPWStr)] internal string name;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LOCALGROUP_USERS_INFO_1
        {
            public IntPtr name;
            public IntPtr comment;
        }


        /*
         * typedef struct _LOCALGROUP_MEMBERS_INFO_3 {
  LPWSTR lgrmi3_domainandname;
} LOCALGROUP_MEMBERS_INFO_3, *PLOCALGROUP_MEMBERS_INFO_3, *LPLOCALGROUP_MEMBERS_INFO_3;
*/
        [StructLayout(LayoutKind.Sequential)]
        public struct LOCALGROUP_MEMBERS_INFO_3
        {
            public string lgrmi3_domainandname;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_INFO_100
        {
            public int platform_id;
            public string computer_name;
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_0
        {
            public string shi0_netname;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            public string shi1_netname;
            public SHARE_TYPE shi1_type;
            public string shi1_remark;
            public SHARE_INFO_1(string sharename, SHARE_TYPE sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }
            public override string ToString()
            {
                return shi1_netname;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SHELLEXECUTEINFO
        {
            public int cbSize;
            public uint fMask;
            public IntPtr hwnd;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpVerb;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpFile;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpParameters;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpDirectory;
            public int nShow;
            public IntPtr hInstApp;
            public IntPtr lpIDList;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpClass;
            public IntPtr hkeyClass;
            public uint dwHotKey;
            public IntPtr hIcon;
            public IntPtr hProcess;
        }
    }
}
