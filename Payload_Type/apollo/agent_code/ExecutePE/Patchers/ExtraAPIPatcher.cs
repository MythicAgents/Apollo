using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using ExecutePE.Helpers;
using ExecutePE.Internals;

namespace ExecutePE.Patchers
{
    internal class ExtraAPIPatcher
    {
        private const int JMP_PATCH_LENGTH = 12;
        private byte[] _originalGetModuleHandleBytes;
        private string _getModuleHandleFuncName;
        private IntPtr _newFuncAlloc;
        private int _newFuncBytesCount;

        public bool PatchAPIs(IntPtr baseAddress)
        {
            _getModuleHandleFuncName = Encoding.UTF8.Equals(Program.encoding) ? "GetModuleHandleW" : "GetModuleHandleA";

#if DEBUG



#endif
            WriteNewFuncToMemory(baseAddress);

            if (PatchAPIToJmpToNewFunc()) return true;
#if DEBUG


#endif
            return false;
        }

        private bool PatchAPIToJmpToNewFunc()
        {
            // Patch the API to jump to out new func code
            var pointerBytes = BitConverter.GetBytes(_newFuncAlloc.ToInt64());

            /*
                0:  48 b8 88 77 66 55 44    movabs rax,<address of newFunc>
                7:  33 22 11
                a:  ff e0                   jmp    rax
             */
            var patchBytes = new List<byte>() { 0x48, 0xB8 };
            patchBytes.AddRange(pointerBytes);

            patchBytes.Add(0xFF);
            patchBytes.Add(0xE0);

            _originalGetModuleHandleBytes =
                Utils.PatchFunction("kernelbase", _getModuleHandleFuncName, patchBytes.ToArray());

            return _originalGetModuleHandleBytes != null;
        }

        private IntPtr WriteNewFuncToMemory(IntPtr baseAddress)
        {
            // Write some code to memory that will return our base address if arg0 is null or revert back to GetModuleAddress if not.
            var newFuncBytes = new List<byte>() { 0x48, 0x85, 0xc9, 0x75, 0x0b };

            var moduleHandle = NativeDeclarations.GetModuleHandle("kernelbase");
            var getModuleHandleFuncAddress = NativeDeclarations.GetProcAddress(moduleHandle, _getModuleHandleFuncName);

            newFuncBytes.Add(0x48);
            newFuncBytes.Add(0xB8);

            var baseAddressPointerBytes = BitConverter.GetBytes(baseAddress.ToInt64());

            newFuncBytes.AddRange(baseAddressPointerBytes);

            newFuncBytes.Add(0xC3);
            newFuncBytes.Add(0x48);
            newFuncBytes.Add(0xB8);

            var pointerBytes = BitConverter.GetBytes(getModuleHandleFuncAddress.ToInt64() + JMP_PATCH_LENGTH);

            newFuncBytes.AddRange(pointerBytes);

            var originalInstructions = new byte[JMP_PATCH_LENGTH];
            Marshal.Copy(getModuleHandleFuncAddress, originalInstructions, 0, JMP_PATCH_LENGTH);
            newFuncBytes.AddRange(originalInstructions);

            newFuncBytes.Add(0xFF);
            newFuncBytes.Add(0xE0);
            /*
            0:  48 85 c9                test   rcx,rcx
            3:  75 0b                   jne    +0x0b
            5:  48 b8 88 77 66 55 44    movabs rax,<Base Address of mapped PE>
            c:  33 22 11
            f:  c3                      ret
            10:  48 b8 88 77 66 55 44   movabs rax,<Back to GetModuleHandle>
            17:  33 22 11
            ... original replaced opcodes...
            1a:  ff e0                  jmp    rax
            */
            _newFuncAlloc = NativeDeclarations.VirtualAlloc(IntPtr.Zero, (uint)newFuncBytes.Count,
                NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
#if DEBUG


#endif
            Marshal.Copy(newFuncBytes.ToArray(), 0, _newFuncAlloc, newFuncBytes.Count);
            _newFuncBytesCount = newFuncBytes.Count;

            NativeDeclarations.VirtualProtect(_newFuncAlloc, (UIntPtr)newFuncBytes.Count,
                NativeDeclarations.PAGE_EXECUTE_READ, out _);
            return _newFuncAlloc;
        }

        public bool RevertAPIs()
        {
#if DEBUG


#endif
            Utils.PatchFunction("kernelbase", _getModuleHandleFuncName, _originalGetModuleHandleBytes);
            Utils.ZeroOutMemory(_newFuncAlloc, _newFuncBytesCount);
            Utils.FreeMemory(_newFuncAlloc);
#if DEBUG


#endif
            return true;
        }
    }
}