using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace ApolloInterop.Classes.Impersonation
{
    public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeTokenHandle() : base(ownsHandle: true) { }

        public SafeTokenHandle(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
    }
}