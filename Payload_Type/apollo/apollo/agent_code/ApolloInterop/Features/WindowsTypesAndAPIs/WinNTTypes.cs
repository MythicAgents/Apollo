using System;
using System.Runtime.InteropServices;
using System.Text;
using static ApolloInterop.Features.WindowsTypesAndAPIs.APIInteropTypes;

namespace ApolloInterop.Features.WindowsTypesAndAPIs;


public static class WinNTTypes
{
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;

        public static LUID FromString(string luid)
        {
            if (String.IsNullOrWhiteSpace(luid))
            {
                return new LUID();
            }
            var uintVal = Convert.ToUInt64(luid, 16);

            return new LUID
            {
                LowPart = (uint)(uintVal & 0xffffffffL),
                HighPart = (int)(uintVal >> 32)
            };
        }

        public bool IsNull => LowPart == 0 && HighPart == 0;

        public override string ToString()
        {
            var value = ((ulong)HighPart << 32) + LowPart;
            return $"0x{value:x}";
        }
    }
    
    
    public readonly struct ACCESS_MASK
    {
        public const uint DELETE = 65536;
        public const uint READ_CONTROL = 131072;
        public const uint SYNCHRONIZE = 1048576;
        public const uint WRITE_DAC = 262144;
        public const uint WRITE_OWNER = 524288;
        public const uint GENERIC_READ = 2147483648;
        public const uint GENERIC_WRITE = 1073741824;
        public const uint GENERIC_EXECUTE = 536870912;
        public const uint GENERIC_ALL = 268435456;
        public const uint STANDARD_RIGHTS_READ = 131072;
        public const uint STANDARD_RIGHTS_WRITE = 131072;
        public const uint STANDARD_RIGHTS_EXECUTE = 131072;
        public const uint STANDARD_RIGHTS_REQUIRED = 983040;
        public const uint STANDARD_RIGHTS_ALL = 2031616;
    }
        
    public struct OBJECT_ATTRIBUTES
    {
        public uint Length;
        public HANDLE RootDirectory;
        public HANDLE<UNICODE_STRING> ObjectName; // -> UNICODE_STRING HANDLE
        public uint Attributes;
        public HANDLE SecurityDescriptor;
        public HANDLE SecurityQualityOfService;
    }
        
    [StructLayout(LayoutKind.Sequential)]
    public record struct UNICODE_STRING 
    {
        public ushort Length;
        public ushort MaximumLength;
        public HANDLE Buffer;

        public UNICODE_STRING(string str)
        {
            Length = (ushort)((str.Length +1) * 2);
            MaximumLength = Length;
            Buffer = (HANDLE)Marshal.StringToHGlobalUni(str);
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(Buffer);
        }
    }

    public struct SID_AND_ATTRIBUTES
    {
        public HANDLE Sid;
        public uint Attributes;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_STATISTICS
    {
        public LUID TokenId;
        public LUID AuthenticationId;
        public ulong ExpirationTime;
        public TOKEN_TYPE TokenType;
        public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        public uint DynamicCharged;
        public uint DynamicAvailable;
        public uint GroupCount;
        public uint PrivilegeCount;
        public LUID ModifiedId;
    }
    
    public struct TOKEN_GROUPS
    {
        public uint GroupCount;
        public SID_AND_ATTRIBUTES Groups;
    }
    
    public record struct TOKEN_SOURCE
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SourceName;
        public LUID SourceIdentifier;
        
        public TOKEN_SOURCE(string name)
        {
            SourceName = new byte[8];
            Encoding.GetEncoding(1252).GetBytes(name, 0, name.Length, SourceName, 0);
        }
        
    }
    
    public enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    public enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }
    
}