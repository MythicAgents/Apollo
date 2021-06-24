#define COMMAND_NAME_UPPER

#if DEBUG
#undef SPAWNTO_x86
#undef SPAWNTO_X64
#define SPAWNTO_X86
#define SPAWNTO_X64
#endif

#if SPAWNTO_X86 || SPAWNTO_X64
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
using Apollo.Evasion;
using Newtonsoft.Json;

namespace Apollo.CommandModules
{
    class SpawnTo
    {

        public struct SpawnToArgs
        {
            public string application;
            public string arguments;
        }

        /// <summary>
        /// Change the sacrificial process that's spawned for certain post-exploitation jobs
        /// such as execute assembly. Valid taskings are spawnto_x64 and spawnto_x86. If the
        /// file does not exist or the file is not of an executable file type, the job
        /// will return an error message.
        /// </summary>
        /// <param name="job">Job associated with this task. The filepath is specified by job.Task.parameters.</param>
        /// <param name="agent">Agent this task is run on.</param>
        /// 
        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            SpawnToArgs args = JsonConvert.DeserializeObject<SpawnToArgs>(job.Task.parameters);

            string path = args.application;
            string arguments = args.arguments;

            if (!File.Exists(path))
            {
                job.SetError($"File {path} does not exist.");
                return;
            }
            FileInfo fileInfo = new FileInfo(path);
            switch(job.Task.command)
            {
#if SPAWNTO_X64
                case "spawnto_x64":
                    try
                    {
                        if (EvasionManager.SetSpawnTo64(fileInfo.FullName, arguments))
                        {
                            if (!string.IsNullOrEmpty(arguments))
                                job.SetComplete($"Changed spawnto_x64 to '{fileInfo.FullName} {arguments}'");
                            else
                                job.SetComplete($"Changed spawnto_x64 to '{fileInfo.FullName} {arguments}");
                        } else
                        {
                            job.SetError($"Could not set spawnto_x64 {fileInfo.FullName} as it is not a valid executable.");
                        }
                    } catch (Exception ex)
                    {
                        job.SetError($"Could not set spawnto_x64 to {fileInfo.FullName}. Reason: {ex.Message}");
                    }
                    break;
#endif
#if SPAWNTO_X86
                case "spawnto_x86":
                    try
                    {
                        if (EvasionManager.SetSpawnTo86(fileInfo.FullName, arguments))
                        {
                            if (!string.IsNullOrEmpty(arguments))
                                job.SetComplete($"Changed spawnto_x86 to '{fileInfo.FullName} {arguments}'");
                            else
                                job.SetComplete($"Changed spawnto_x86 to '{fileInfo.FullName} {arguments}");
                        }
                        else
                        {
                            job.SetError($"Could not set spawnto_x86 {fileInfo.FullName} as it is not a valid executable.");
                        }
                    }
                    catch (Exception ex)
                    {
                        job.SetError($"Could not set spawnto_x86 to {fileInfo.FullName}. Reason: {ex.Message}");
                    }
                    break;
#endif
                default:
                    job.SetError("Unsupported code path.");
                    break;
            }
        }

        /// <summary>
        /// Interrogate a file to see if it's a valid executable file-type.
        /// </summary>
        /// <param name="fileName">Name of the file whose executable status is to be determined.</param>
        /// <returns>TRUE if executable, FALSE otherwise.</returns>
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private static bool IsExecutable(string fileName)
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
    }
}
#endif