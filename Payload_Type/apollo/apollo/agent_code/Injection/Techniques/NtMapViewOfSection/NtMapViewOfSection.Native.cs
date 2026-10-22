using System;
using System.Runtime.InteropServices;

namespace Injection.Techniques.MapViewOfSection
{
    internal delegate uint NtCreateSection(
        out IntPtr sectionHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        ref long maximumSize,
        uint sectionPageProtection,
        uint allocationAttributes,
        IntPtr fileHandle);

    internal delegate uint NtMapViewOfSection(
        IntPtr sectionHandle,
        IntPtr processHandle,
        ref IntPtr baseAddress,
        IntPtr zeroBits,
        IntPtr commitSize,
        IntPtr sectionOffset,
        ref ulong viewSize,
        uint inheritDisposition,
        uint allocationType,
        uint win32Protect);

    internal delegate uint NtUnmapViewOfSection(
        IntPtr processHandle,
        IntPtr baseAddress);

    internal delegate IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId);

    internal enum ThreadAccessRights : UInt32
    {
        SYNCHRONIZE = 0x00100000,
        THREAD_DIRECT_IMPERSONATION = 0x0200,
        THREAD_GET_CONTEXT = 0x0008,
        THREAD_IMPERSONATE = 0x0100,
        THREAD_QUERY_INFORMATION = 0x0040,
        THREAD_QUERY_LIMITED_INFORMATION = 0x0800,
        THREAD_SET_CONTEXT = 0x0010,
        THREAD_SET_INFORMATION = 0x0020,
        THREAD_SET_LIMITED_INFORMATION = 0x0400,
        THREAD_SET_THREAD_TOKEN = 0x0080,
        THREAD_SUSPEND_RESUME = 0x0002,
        THREAD_TERMINATE = 0x0001,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        THREAD_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
    }

    internal delegate IntPtr OpenThread(ThreadAccessRights dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    internal delegate bool GetThreadContext(IntPtr hThread, ref CONTEXT context);
    internal delegate bool SetThreadContext(IntPtr hThread, ref CONTEXT context);
    internal delegate uint NtResumeThread(IntPtr threadHandle, out uint previousSuspendCount);

    [StructLayout(LayoutKind.Sequential)]
    internal struct CONTEXT
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;

        public uint ContextFlags;
        public uint MxCsr;

        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;

        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;

        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;

        // The x64 equivalent of FLOATING_SAVE_AREA
        public XMM_SAVE_AREA32 FltSave;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public M128A[] VectorRegister;

        public ulong VectorControl;

        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct M128A
    {
        public ulong Low;
        public ulong High;
    }

    // Floating point save area for x64 (replaces FLOATING_SAVE_AREA)
    [StructLayout(LayoutKind.Sequential)]
    internal struct XMM_SAVE_AREA32
    {
        public ushort ControlWord;
        public ushort StatusWord;
        public byte TagWord;
        public byte Reserved1;
        public ushort ErrorOpcode;
        public uint ErrorOffset;
        public ushort ErrorSelector;
        public ushort Reserved2;
        public uint DataOffset;
        public ushort DataSelector;
        public ushort Reserved3;
        public uint MxCsr;
        public uint MxCsrMask;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public M128A[] FloatRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public M128A[] XmmRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] Reserved4;
    }
}
