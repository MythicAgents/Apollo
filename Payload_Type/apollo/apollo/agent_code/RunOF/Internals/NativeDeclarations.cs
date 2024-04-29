using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;

namespace RunOF.Internals
{
    unsafe class NativeDeclarations
    {


            internal const uint MEM_COMMIT = 0x1000;
            internal const uint MEM_RESERVE = 0x2000;
            internal const uint MEM_RELEASE = 0x00008000;



        internal const uint PAGE_EXECUTE_READWRITE = 0x40;
        internal const uint PAGE_READWRITE = 0x04;
        internal const uint PAGE_EXECUTE_READ = 0x20;
        internal const uint PAGE_EXECUTE = 0x10;
        internal const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        internal const uint PAGE_NOACCESS = 0x01;
        internal const uint PAGE_READONLY = 0x02;
        internal const uint PAGE_WRITECOPY = 0x08;

        internal const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        internal const uint IMAGE_SCN_MEM_READ = 0x40000000;
        internal const uint IMAGE_SCN_MEM_WRITE = 0x80000000;


        [StructLayout(LayoutKind.Sequential)]
            public unsafe struct IMAGE_BASE_RELOCATION
            {
                public uint VirtualAdress;
                public uint SizeOfBlock;
            }

            [DllImport("kernel32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetStdHandle(int nStdHandle);

            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_ATTRIBUTES
            {
                public int nLength;
                public unsafe byte* lpSecurityDescriptor;
                public int bInheritHandle;
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer,
                uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

            [DllImport("kernel32.dll")]
            public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
                ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, uint processInformationLength, IntPtr returnLength);

            [DllImport("kernel32")]
            public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, uint size, uint flAllocationType, uint flProtect);
       
            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            internal static extern bool VirtualFree(IntPtr pAddress, uint size, uint freeType);
        
            [DllImport("kernel32.dll")]
            public static extern bool HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);

            [DllImport("kernel32")]
            public static extern IntPtr GetProcessHeap();

            [DllImport("kernel32")]
            public static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwBytes);

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern IntPtr LoadLibrary(string lpFileName);

            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetCommandLine();

            [DllImport("kernel32.dll", SetLastError = true)]
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            [SuppressUnmanagedCodeSecurity]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CloseHandle(IntPtr hObject);

            [DllImport("kernel32")]
            public static extern IntPtr CreateThread(

              IntPtr lpThreadAttributes,
              uint dwStackSize,
              IntPtr lpStartAddress,
              IntPtr param,
              uint dwCreationFlags,
              IntPtr lpThreadId
              );

            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("kernel32.dll")]
            public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("kernel32")]
            public static extern uint WaitForSingleObject(

              IntPtr hHandle,
              uint dwMilliseconds
              );



            [DllImport("kernel32.dll")]
            public static extern bool GetExitCodeThread(IntPtr hThread, out int lpExitcode);


        [DllImport("Kernel32.dll", EntryPoint = "RtlZeroMemory", SetLastError = false)]
        public static extern void ZeroMemory(IntPtr dest, int size);




        [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_BASIC_INFORMATION
            {
                public uint ExitStatus;
                public IntPtr PebAddress;
                public UIntPtr AffinityMask;
                public int BasePriority;
                public UIntPtr UniqueProcessId;
                public UIntPtr InheritedFromUniqueProcessId;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct UNICODE_STRING : IDisposable
            {
                public ushort Length;
                public ushort MaximumLength;
                private IntPtr buffer;

                public UNICODE_STRING(string s)
                {
                    Length = (ushort)(s.Length * 2);
                    MaximumLength = (ushort)(Length + 2);
                    buffer = Marshal.StringToHGlobalUni(s);
                }

                public void Dispose()
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                }

                public override string ToString()
                {
                    return Marshal.PtrToStringUni(buffer);
                }

            }

            public enum AllocationProtectEnum : uint
            {
                PAGE_EXECUTE = 0x00000010,
                PAGE_EXECUTE_READ = 0x00000020,
                PAGE_EXECUTE_READWRITE = 0x00000040,
                PAGE_EXECUTE_WRITECOPY = 0x00000080,
                PAGE_NOACCESS = 0x00000001,
                PAGE_READONLY = 0x00000002,
                PAGE_READWRITE = 0x00000004,
                PAGE_WRITECOPY = 0x00000008,
                PAGE_GUARD = 0x00000100,
                PAGE_NOCACHE = 0x00000200,
                PAGE_WRITECOMBINE = 0x00000400
            }

            public enum HeapAllocFlags : uint
            {
            HEAP_GENERATE_EXCEPTIONS = 0x00000004,
            HEAP_NO_SERIALIZE = 0x00000001,
            HEAP_ZERO_MEMORY = 0x00000008,

            }

        public enum WaitEventEnum : uint
        {
            WAIT_ABANDONED = 0x00000080,
            WAIT_OBJECT_0 = 00000000,
            WAIT_TIMEOUT  = 00000102,
            WAIT_FAILED = 0xFFFFFFFF,
        }

            public enum StateEnum : uint
            {
                MEM_COMMIT = 0x1000,
                MEM_FREE = 0x10000,
                MEM_RESERVE = 0x2000
            }

            public enum TypeEnum : uint
            {
                MEM_IMAGE = 0x1000000,
                MEM_MAPPED = 0x40000,
                MEM_PRIVATE = 0x20000
            }

            public struct MEMORY_BASIC_INFORMATION
            {
                public IntPtr BaseAddress;
                public IntPtr AllocationBase;
                public AllocationProtectEnum AllocationProtect;
                public IntPtr RegionSize;
                public StateEnum State;
                public AllocationProtectEnum Protect;
                public TypeEnum Type;
            }
        }



    }

