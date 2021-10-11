using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace DPAPI
{
    public static class Win32
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DataBlob : IDisposable
        {
            public int cbData;
            public IntPtr pbData;

            public DataBlob(byte[] data)
            {
                cbData = data.Length;
                pbData = Marshal.AllocHGlobal(data.Length);
                Marshal.Copy(data, 0, pbData, data.Length);
            }

            public void Dispose()
            {
                if (pbData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pbData);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CryptProtectPromptStruct
        {
            public int cbSize;
            public int dwPromptFlags;
            public IntPtr hwndApp;
            public string szPrompt;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DpapiModule
        {
            public String sModName;
            public int iModVersion;
            public int iModSize;
            public IntPtr pMod;
            public Byte[] bMod;
        }
    }
}
