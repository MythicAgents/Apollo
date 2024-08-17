using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ApolloInterop.Utils;

namespace ExecutePE.Patchers
{
    using FunctionHook = Dictionary<string, IFunctionHook>;

    internal class IATHooks()
    {
        private Dictionary<string, FunctionHook> _libraryHooks = new()
        {
            {
                "msvcrt.dll", new()
                {
                    {"__wgetmainargs", new GetMainArgsFunctionHook() },
                }
            },
        };

        public bool ApplyHook(string dllname, string dllFuncName, IntPtr iatAddress, IntPtr originalFunction)
        {
            if (_libraryHooks.TryGetValue(dllname.ToLower(), out var functionHooks))
            {
                if (functionHooks.TryGetValue(dllFuncName, out var hookCallback))
                {
                    return hookCallback.ApplyHook(iatAddress, originalFunction);
                }
            }
            return false;
        }
    }

    internal class GetMainArgsFunctionHook : IFunctionHook
    {
        private IntPtr? _hookAddress;

        // NASM assembly
        //
        // global __wgetmainargs
        // section .text
        // ; __wgetmainargs(int *_Argc, wchar_t ***_Argv, wchar_t ***_Envp, int options, int *_newmode)
        // __wgetmainargs:
        //     push r12
        //     push r13
        //     sub rsp, 8 + 0x20
        //     mov r12, rcx ; Save *_Argc
        //     mov r13, rdx ; Save *_Argv
        //
        //     call [rel GetCommandLineW]
        //     test rax, rax
        //     jz __wgetmainargs_ret
        //
        //     mov rcx, rax ; lpCmdline
        //     lea rdx, [rsp+0x20] ; pNumArgs
        //     call [rel CommandLineToArgvW]
        //     test rax, rax
        //     jz __wgetmainargs_ret
        //
        //     mov [r13], rax
        //     mov eax, dword [rsp+0x20]
        //     mov dword [r12], eax
        //
        // __wgetmainargs_ret:
        //     add rsp, 8 + 0x20
        //     pop r13
        //     pop r12
        //     ret
        //     align 8
        // GetCommandLineW:
        //     dq 0
        // CommandLineToArgvW:
        //     dq 0
        private List<byte> _hookBytes = [
            0x41, 0x54, 0x41, 0x55, 0x48, 0x83, 0xec, 0x28, 0x49, 0x89, 0xcc, 0x49,
            0x89, 0xd5, 0xff, 0x15, 0x34, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74,
            0x1f, 0x48, 0x89, 0xc1, 0x48, 0x8d, 0x54, 0x24, 0x20, 0xff, 0x15, 0x29,
            0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x0c, 0x49, 0x89, 0x45, 0x00,
            0x8b, 0x44, 0x24, 0x20, 0x41, 0x89, 0x04, 0x24, 0x48, 0x83, 0xc4, 0x28,
            0x41, 0x5d, 0x41, 0x5c, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
        ];

        public bool ApplyHook(IntPtr iatAddress, IntPtr originalFunction)
        {
            var kernelbase = NativeDeclarations.GetModuleHandle("kernelbase");
            if (kernelbase == IntPtr.Zero)
            {
                return false;
            }

            var getCommandLineWAddress = NativeDeclarations.GetProcAddress(kernelbase, "GetCommandLineW");
            if (getCommandLineWAddress == IntPtr.Zero)
            {
                return false;
            }

            var commandLineToArgvWAddress = NativeDeclarations.GetProcAddress(kernelbase, "CommandLineToArgvW");
            if (commandLineToArgvWAddress == IntPtr.Zero)
            {
                return false;
            }

            _hookBytes.AddRange(BitConverter.GetBytes(getCommandLineWAddress.ToInt64()));
            _hookBytes.AddRange(BitConverter.GetBytes(commandLineToArgvWAddress.ToInt64()));

            var hookMemory = NativeDeclarations.VirtualAlloc(
                IntPtr.Zero,
                (uint)_hookBytes.Count,
                NativeDeclarations.MEM_COMMIT,
                NativeDeclarations.PAGE_READWRITE
            );

            if (hookMemory == null)
            {
                return false;
            }

            _hookAddress = hookMemory;

            Marshal.Copy(_hookBytes.ToArray(), 0, hookMemory, _hookBytes.Count);

            if (!NativeDeclarations.VirtualProtect(
                hookMemory,
                (UIntPtr)_hookBytes.Count,
                NativeDeclarations.PAGE_EXECUTE_READ,
                out _)
            )
            {
                return false;
            }

            Marshal.WriteInt64(iatAddress, hookMemory.ToInt64());
            return true;
        }

        ~GetMainArgsFunctionHook()
        {
            if (_hookAddress is IntPtr address)
            {
                NativeDeclarations.VirtualFree(
                    address,
                    (uint)_hookBytes.Count,
                    NativeDeclarations.MEM_RELEASE
                );
            }
        }
    }

    internal interface IFunctionHook
    {
        bool ApplyHook(IntPtr iatAddress, IntPtr originalFunction);
    }
}
