using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace ExecutePE.Helpers
{
    internal static class Utils
    {
        internal static byte[]? PatchFunction(string dllName, string funcName, byte[] patchBytes)
        {
            var moduleHandle = NativeDeclarations.GetModuleHandle(dllName);
            var pFunc = NativeDeclarations.GetProcAddress(moduleHandle, funcName);
            var originalBytes = new byte[patchBytes.Length];
            Marshal.Copy(pFunc, originalBytes, 0, patchBytes.Length);

            var result = NativeDeclarations.VirtualProtect(pFunc, (UIntPtr)patchBytes.Length,
                NativeDeclarations.PAGE_EXECUTE_READWRITE, out var oldProtect);
            if (!result)
            {
                return null;
            }
            Marshal.Copy(patchBytes, 0, pFunc, patchBytes.Length);

            result = NativeDeclarations.VirtualProtect(pFunc, (UIntPtr)patchBytes.Length, oldProtect, out _);
            if (!result)
            {
            }
            return originalBytes;
        }

        internal static bool PatchAddress(IntPtr pAddress, IntPtr newValue)
        {
            var result = NativeDeclarations.VirtualProtect(pAddress, (UIntPtr)IntPtr.Size,
                NativeDeclarations.PAGE_EXECUTE_READWRITE, out var oldProtect);
            if (!result)
            {
                return false;
            }

            Marshal.WriteIntPtr(pAddress, newValue);
            result = NativeDeclarations.VirtualProtect(pAddress, (UIntPtr)IntPtr.Size, oldProtect, out _);
            if (!result)
            {
                return false;
            }
            return true;
        }

        internal static bool ZeroOutMemory(IntPtr start, int length)
        {
            var result = NativeDeclarations.VirtualProtect(start, (UIntPtr)length, NativeDeclarations.PAGE_READWRITE,
                out var oldProtect);
            if (!result)
            {
            }

            var zeroes = new byte[length];
            for (var i = 0; i < zeroes.Length; i++)
            {
                zeroes[i] = 0x00;
            }

            Marshal.Copy(zeroes.ToArray(), 0, start, length);

            result = NativeDeclarations.VirtualProtect(start, (UIntPtr)length, oldProtect, out _);
            if (!result)
            {
                return false;
            }

            return true;
        }

        internal static void FreeMemory(IntPtr address)
        {
            NativeDeclarations.VirtualFree(address, 0, NativeDeclarations.MEM_RELEASE);
        }

        internal static IntPtr GetPointerToPeb()
        {
            var currentProcessHandle = NativeDeclarations.GetCurrentProcess();
            var processBasicInformation =
                Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeDeclarations.PROCESS_BASIC_INFORMATION)));
            var outSize = Marshal.AllocHGlobal(sizeof(long));
            var pPEB = IntPtr.Zero;

            var result = NativeDeclarations.NtQueryInformationProcess(currentProcessHandle, 0, processBasicInformation,
                (uint)Marshal.SizeOf(typeof(NativeDeclarations.PROCESS_BASIC_INFORMATION)), outSize);

            NativeDeclarations.CloseHandle(currentProcessHandle);
            Marshal.FreeHGlobal(outSize);

            if (result == 0)
            {
                pPEB = ((NativeDeclarations.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(processBasicInformation,
                    typeof(NativeDeclarations.PROCESS_BASIC_INFORMATION))).PebAddress;
            }
            else
            {
                var error = NativeDeclarations.GetLastError();
            }

            Marshal.FreeHGlobal(processBasicInformation);

            return pPEB;
        }
    }
}
