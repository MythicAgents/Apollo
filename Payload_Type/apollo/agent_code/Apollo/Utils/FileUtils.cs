using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Apollo.Jobs;
using System.IO;
using System.Security.Permissions;
using static Native.Methods;
using static Native.Structures;
using static Native.Enums;
using System.Runtime.InteropServices;
using Apollo.Tasks;
using System.Security.Cryptography;

namespace Apollo.Utils
{
    static class FileUtils
    {

        /// <summary>
        /// Interrogate a file to see if it's a valid executable file-type.
        /// </summary>
        /// <param name="fileName">Name of the file whose executable status is to be determined.</param>
        /// <returns>TRUE if executable, FALSE otherwise.</returns>
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        internal static bool IsExecutable(string fileName)
        {
            // https://stackoverflow.com/questions/3693891/how-to-determine-if-a-file-is-executable
            if (fileName == null)
            {
                throw new ArgumentNullException("fileName");
            }

            ExecutableType executableType = ExecutableType.Unknown;
            IntPtr ptr;
            if (File.Exists(fileName))
            {
                // Try to fill the same SHFILEINFO struct for the exe type. The returned pointer contains the encoded 
                // executable type data.
                ptr = IntPtr.Zero;
                SHFILEINFO shFileInfo = new SHFILEINFO();
                ptr = SHGetFileInfo(fileName, (uint)FileAttributes.Normal, ref shFileInfo, Marshal.SizeOf(typeof(SHFILEINFO)), SHGFI.EXETYPE);

                // We need to split the returned pointer up into the high and low order words. These are important
                // because they help distinguish some of the types. The possible values are:
                //
                // Value                                            Meaning
                // ----------------------------------------------------------------------------------------------
                // 0                                                Nonexecutable file or an error condition. 
                // LOWORD = NE or PE and HIWORD = Windows version   Microsoft Windows application.
                // LOWORD = MZ and HIWORD = 0                       Windows 95, Windows 98: Microsoft MS-DOS .exe, .com, or .bat file
                //                                                  Microsoft Windows NT, Windows 2000, Windows XP: MS-DOS .exe or .com file 
                // LOWORD = PE and HIWORD = 0                       Windows 95, Windows 98: Microsoft Win32 console application 
                //                                                  Windows NT, Windows 2000, Windows XP: Win32 console application or .bat file 
                // MZ = 0x5A4D - DOS signature.
                // NE = 0x454E - OS/2 signature.
                // LE = 0x454C - OS/2 LE or VXD signature.
                // PE = 0x4550 - Win32/NT signature.

                int wparam = ptr.ToInt32();
                int loWord = wparam & 0xffff;
                int hiWord = wparam >> 16;

                if (wparam == 0)
                {
                    //executableType = Shell32.ExecutableType.Unknown;
                    return false;
                }
                else
                {
                    if (hiWord == 0x0000)
                    {
                        if (loWord == 0x5A4D)
                        {
                            // The file is an MS-DOS .exe, .com, or .bat
                            //executableType = Shell32.ExecutableType.DOS;
                            return true;
                        }
                        else if (loWord == 0x4550)
                        {
                            //executableType = Shell32.ExecutableType.Win32Console;
                            return true;
                        }
                    }
                    else
                    {
                        if (loWord == 0x454E || loWord == 0x4550)
                        {
                            //executableType = Shell32.ExecutableType.Windows;
                            return true;
                        }
                        else if (loWord == 0x454C)
                        {
                            //executableType = Shell32.ExecutableType.Windows;
                            return true;
                        }
                    }
                }
            }

            return false;
        }


        internal static string GetFileMD5(string filename)
        {
            try
            {
                FileInfo finfo = new FileInfo(filename);
                string hash;
                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(finfo.FullName))
                    {
                        hash = BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                    }
                }
                return hash;
            } catch (Exception ex)
            { return ""; }
        }
    }
}
