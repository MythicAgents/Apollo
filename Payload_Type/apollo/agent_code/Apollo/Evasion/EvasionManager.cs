#define COMMAND_NAME_UPPER

#if DEBUG
#undef SPAWNTO_x86
#undef SPAWNTO_X64
#undef PPID
#undef BLOCKDLLS
#define BLOCKDLLS
#define SPAWNTO_X86
#define SPAWNTO_X64
#define PPID
#endif

using Apollo.CommandModules;
using Apollo.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


namespace Apollo.Evasion
{
    internal static class EvasionManager
    {
        private static string _spawnTo64 = "C:\\Windows\\System32\\rundll32.exe";
        private static string _spawnTo64Args = "";
        private static string _spawnTo86 = "C:\\Windows\\SysWOW64\\rundll32.exe";
        private static string _spawnTo86Args = "";
        private static int _parentProcessId = System.Diagnostics.Process.GetCurrentProcess().Id;
        private static bool _blockDLLs = false;

        internal struct SacrificialProcessStartupInformation
        {
            internal string Application;
            internal string Arguments;
            internal int ParentProcessId;
            internal bool BlockDlls;
        }

        internal static SacrificialProcessStartupInformation GetSacrificialProcessStartupInformation()
        {
            SacrificialProcessStartupInformation results = new SacrificialProcessStartupInformation();
            if (IntPtr.Size == 8)
            {
                results.Application = _spawnTo64;
                results.Arguments = _spawnTo64Args;
            }
            else
            {
                results.Application = _spawnTo86;
                results.Arguments = _spawnTo86;
            }
            results.ParentProcessId = _parentProcessId;
            results.BlockDlls = _blockDLLs;
            return results;
        }

#if SPAWNTO_X64
        internal static bool SetSpawnTo64(string fileName, string args = "")
        {
            bool bRet = false;
            if (FileUtils.IsExecutable(fileName))
            {
                _spawnTo64 = fileName;
                if (!string.IsNullOrEmpty(args))
                    _spawnTo64Args = args;
                bRet = true;
            }
            return bRet;
        }
#endif
#if SPAWNTO_X86
        internal static bool SetSpawnTo86(string fileName, string args = "")
        {
            bool bRet = false;
            if (FileUtils.IsExecutable(fileName))
            {
                _spawnTo86 = fileName;
                if (!string.IsNullOrEmpty(args))
                    _spawnTo86Args = args;
                bRet = true;
            }
            return bRet;
        }
#endif
#if PPID
        internal static bool SetParentProcessId(int processId)
        {
            bool bRet = false;
            try
            {
                System.Diagnostics.Process.GetProcessById(processId);
                bRet = true;
                _parentProcessId = processId;
            } catch { }
            return bRet;
        }
#endif
#if BLOCKDLLS
        internal static bool BlockDlls(bool status)
        {
            _blockDLLs = status;
            return true;
        }
#endif
    }
}
