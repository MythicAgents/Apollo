using System;
using System.Collections.Generic;
using ExecutePE.Helpers;

namespace ExecutePE.Patchers
{
    internal class ExitPatcher
    {
        private byte[]? _terminateProcessOriginalBytes;
        private byte[]? _ntTerminateProcessOriginalBytes;
        private byte[]? _rtlExitUserProcessOriginalBytes;
        private byte[]? _corExitProcessOriginalBytes;

        public bool PatchExit()
        {
            var hKernelbase = NativeDeclarations.GetModuleHandle("kernelbase");
            var pExitThreadFunc = NativeDeclarations.GetProcAddress(hKernelbase, "ExitThread");
            var exitThreadPatchBytes = new List<byte>() { 0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8 };
            /*
                mov rcx, 0x0 #takes first arg
                mov rax, <ExitThread> # 
                push rax
                ret
             */
            var pointerBytes = BitConverter.GetBytes(pExitThreadFunc.ToInt64());

            exitThreadPatchBytes.AddRange(pointerBytes);

            exitThreadPatchBytes.Add(0x50);
            exitThreadPatchBytes.Add(0xC3);
            _terminateProcessOriginalBytes =
                Utils.PatchFunction("kernelbase", "TerminateProcess", exitThreadPatchBytes.ToArray());
            if (_terminateProcessOriginalBytes == null)
            {
                return false;
            }

            _corExitProcessOriginalBytes =
                Utils.PatchFunction("mscoree", "CorExitProcess", exitThreadPatchBytes.ToArray());
            if (_corExitProcessOriginalBytes == null)
            {
                return false;
            }

            _ntTerminateProcessOriginalBytes =
                Utils.PatchFunction("ntdll", "NtTerminateProcess", exitThreadPatchBytes.ToArray());
            if (_ntTerminateProcessOriginalBytes == null)
            {
                return false;
            }

            _rtlExitUserProcessOriginalBytes =
                Utils.PatchFunction("ntdll", "RtlExitUserProcess", exitThreadPatchBytes.ToArray());
            if (_rtlExitUserProcessOriginalBytes == null)
            {
                return false;
            }

            return true;
        }

        internal void ResetExitFunctions()
        {
            if (_terminateProcessOriginalBytes != null)
            {
                Utils.PatchFunction("kernelbase", "TerminateProcess", _terminateProcessOriginalBytes);
            }

            if (_corExitProcessOriginalBytes != null)
            {
                Utils.PatchFunction("mscoree", "CorExitProcess", _corExitProcessOriginalBytes);
            }

            if (_ntTerminateProcessOriginalBytes != null)
            {
                Utils.PatchFunction("ntdll", "NtTerminateProcess", _ntTerminateProcessOriginalBytes);
            }

            if (_rtlExitUserProcessOriginalBytes != null)
            {
                Utils.PatchFunction("ntdll", "RtlExitUserProcess", _rtlExitUserProcessOriginalBytes);
            }
        }
    }
}
