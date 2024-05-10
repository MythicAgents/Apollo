using System;
using System.Text;
using static ApolloInterop.Features.WindowsTypesAndAPIs.WinNTTypes;
using static ApolloInterop.Features.WindowsTypesAndAPIs.APIInteropTypes;
namespace ApolloInterop.Features.WindowsTypesAndAPIs;

public static class LSATypes
{
    public struct LSA_AUTH_INFORMATION 
    { 
        long         LastUpdateTime;
        uint         AuthType;
        uint         AuthInfoLength;
        HANDLE       AuthInfo;
    }
    
    public record struct LSA_OUT_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public HANDLE<char> Buffer;

        public override string ToString()
        {
            //the handle is a pointer to only the first character of the string we  want to return
            //we must read each following byte for the length of the string to get the full string
            StringBuilder sb = new();
            HANDLE<char> currentCharHandle = Buffer;
            
            //read each character from the buffer
            for (int i = 0; i < Length; i++)
            {
                char returnedChar = currentCharHandle.GetValue();
                //if the character is a separator or control char, we don't want to include it in the string
                if(Char.IsSeparator(returnedChar) is false && Char.IsControl(returnedChar) is false)
                {
                    sb.Append(returnedChar);
                }
                //move the pointer to the next character
                currentCharHandle = currentCharHandle.IncrementBy(1);
            }
            string result = sb.ToString();
            return result;
        }

        public LSA_OUT_STRING(string str)
        {
            Length = (ushort)str.Length;
            MaximumLength = (ushort)(str.Length + 1);
            Buffer = new(str.ToCharArray()[0]);
        }
    }
    
    public record struct LSA_IN_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public string Buffer;
        
        
        public LSA_IN_STRING(string str)
        {
            Length = (ushort)str.Length;
            MaximumLength = (ushort)(str.Length + 1);
            Buffer = str;
        }
    }
    
    
    /// <summary>
    /// Data provided by lsa after a call to LsaGetLogonSessionData
    /// Make sure to convert this to a LogonSessionData object before accessing its properties to avoid issues
    /// </summary>
    public record struct SECURITY_LOGON_SESSION_DATA
    {
        public uint Size;
        public LUID LogonId;
        public LSA_OUT_STRING UserName;
        public LSA_OUT_STRING LogonDomain;
        public LSA_OUT_STRING AuthenticationPackage;
        public uint LogonType;
        public uint Session;
        public HANDLE Sid;
        public long LogonTime;
        public LSA_OUT_STRING LogonServer;
        public LSA_OUT_STRING DnsDomainName;
        public LSA_OUT_STRING Upn;
    }

    public struct QUOTA_LIMITS
    {
        public uint PagedPoolLimit;
        public uint NonPagedPoolLimit;
        public uint MinimumWorkingSetSize;
        public uint MaximumWorkingSetSize;
        public uint PagefileLimit;
        public long TimeLimit;
    }
    
}