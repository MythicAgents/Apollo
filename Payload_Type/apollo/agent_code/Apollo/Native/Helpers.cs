using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static Native.Enums;
using static Native.Structures;
using static Native.Methods;

namespace Native
{
    internal static class Helpers
    {
        public static IntPtr LsaRegisterLogonProcessHelper()
        {
            // helper that establishes a connection to the LSA server and verifies that the caller is a logon application
            // used for Kerberos ticket enumeration

            const string logonProcessName = "User32LogonProcess";
            LSA_STRING_IN lsaString;

            lsaString.Length = (ushort)logonProcessName.Length;
            lsaString.MaximumLength = (ushort)(logonProcessName.Length + 1);
            lsaString.Buffer = logonProcessName;

            var ret = LsaRegisterLogonProcess(lsaString, out var lsaHandle, out _);

            return lsaHandle;
        }
    }
}
