using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes.Api
{
    public class Library
    {
        public string Value { get; private set; }
        private Library(string libraryName)
        {
            Value = libraryName;
        }

        public override string ToString()
        {
            return Value;
        }

        public static Library NTDLL { get { return new Library("ntdll.dll"); } }
        public static Library ADVAPI32 { get { return new Library("advapi32.dll"); } }
        public static Library KERNEL32 { get { return new Library("kernel32.dll"); } }
        public static Library USER32 { get { return new Library("user32.dll"); } }
        public static Library USERENV { get { return new Library("userenv.dll"); } }
        public static Library SHELL32 { get { return new Library("shell32.dll"); } }
        public static Library SAMCLI { get { return new Library("samcli.dll"); } }
        public static Library NETUTILS { get { return new Library("netutils.dll"); } }
        public static Library NETAPI32 { get { return new Library("Netapi32.dll"); } }
        public static Library SRVCLI { get { return new Library("srvcli.dll"); } }
        public static Library IPHLPAPI { get { return new Library("iphlpapi.dll"); } }
    }
}
