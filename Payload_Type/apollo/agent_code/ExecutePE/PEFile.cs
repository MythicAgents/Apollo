using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;


namespace ExecutePE
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ImageDosHeader
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
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U2, SizeConst = 4)]
        public ushort[] e_res;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U2, SizeConst = 10)]
        public ushort[] e_res2;
        public uint e_lfanew;
    }

    public enum ImageFileMachine : ushort
    {
        MachineI386 = 0x014c,
        MachineIA64 = 0x200,
        MachineAMD64 = 0x8664
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ImageFileHeader
    {
        public ImageFileMachine Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ImageDataDirectory
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ImageBaseRelocation
    {
        public uint VirtualAddress;
        public uint SizeOfBlock;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ImageImportDescriptor
    {
        [FieldOffset(0)]
        public uint Characteristics;

        [FieldOffset(0)]
        public uint OriginalFirstThunk;

        [FieldOffset(4)]
        public uint TimeDateStamp;

        [FieldOffset(8)]
        public uint ForwarderChain;

        [FieldOffset(12)]
        public uint Name;

        [FieldOffset(16)]
        public uint FirstThunk;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ImageThunkData32
    {
        [FieldOffset(0)]
        public uint ForwarderString;
        [FieldOffset(0)]
        public uint Function;
        [FieldOffset(0)]
        public uint Ordinal;
        [FieldOffset(0)]
        public uint AddressOfData;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ImageThunkData64
    {
        [FieldOffset(0)]
        public ulong ForwarderString;
        [FieldOffset(0)]
        public ulong Function;
        [FieldOffset(0)]
        public ulong Ordinal;
        [FieldOffset(0)]
        public ulong AddressOfData;
    }

    [StructLayout(LayoutKind.Explicit)]
    public unsafe struct ImageImportByName
    {
        [FieldOffset(0)]
        public ushort Hint;
        [FieldOffset(2)]
        public fixed char Name[1];
    }

    public struct ImageOptionalHeader32
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
        public ImageDataDirectory ExportDirectory;
        public ImageDataDirectory ImportDirectory;
        public ImageDataDirectory ResourceDirectory;
        public ImageDataDirectory ExceptionDirectory;
        public ImageDataDirectory SecurityDirectory;
        public ImageDataDirectory RelocationDirectory;
        public ImageDataDirectory DebugDirectory;
        public ImageDataDirectory ArchitectureDirectory;
        public ImageDataDirectory GlobalPointerDirectory;
        public ImageDataDirectory TlsDirectory;
        public ImageDataDirectory ConfigDirectory;
        public ImageDataDirectory BoundImportDirectory;
        public ImageDataDirectory IATDirectory;
        public ImageDataDirectory DelayImportDirectory;
        public ImageDataDirectory CorMetaDirectory;
        public ImageDataDirectory Reserved;
    }

    public struct ImageOptionalHeader64
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
        public ImageDataDirectory ExportDirectory;
        public ImageDataDirectory ImportDirectory;
        public ImageDataDirectory ResourceDirectory;
        public ImageDataDirectory ExceptionDirectory;
        public ImageDataDirectory SecurityDirectory;
        public ImageDataDirectory RelocationDirectory;
        public ImageDataDirectory DebugDirectory;
        public ImageDataDirectory ArchitectureDirectory;
        public ImageDataDirectory GlobalPointerDirectory;
        public ImageDataDirectory TlsDirectory;
        public ImageDataDirectory ConfigDirectory;
        public ImageDataDirectory BoundImportDirectory;
        public ImageDataDirectory IATDirectory;
        public ImageDataDirectory DelayImportDirectory;
        public ImageDataDirectory CorMetaDirectory;
        public ImageDataDirectory Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ImageNtHeaders32
    {
        public uint Signature;
        public ImageFileHeader FileHeader;
        public ImageOptionalHeader32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ImageNtHeaders64
    {
        public uint Signature;
        public ImageFileHeader FileHeader;
        public ImageOptionalHeader64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct Misc
    {
        [FieldOffset(0)]
        public uint PhysicalAddress;
        [FieldOffset(0)]
        public uint VirtualSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ImageSectionHeader
    {
        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U1, SizeConst = 8)]
        public byte[] Name;
        public Misc Misc;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLineNumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLineNumbers;
        public uint Characteristics;

        public string GetName()
        {
            return Encoding.UTF8.GetString(Name);
        }
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ImageTlsDirectory32
    {
        [FieldOffset(0)]
        public uint StartAddressOfRawdata;
        [FieldOffset(4)]
        public uint EndAddressOfRawData;
        [FieldOffset(8)]
        public uint AddressOfIndex;  // PDWORD
        [FieldOffset(12)]
        public uint AddressOfCallBacks;  // PIMAGE_TLS_CALLBACK *
        [FieldOffset(16)]
        public uint SizeOfZeroFill;
        [FieldOffset(20)]
        public uint Characteristics; // There's more but we don't care about them
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ImageTlsDirectory64
    {
        [FieldOffset(0)]
        public ulong StartAddressOfRawdata;
        [FieldOffset(8)]
        public ulong EndAddressOfRawData;
        [FieldOffset(16)]
        public ulong AddressOfIndex;  // PDWORD
        [FieldOffset(24)]
        public ulong AddressOfCallBacks;  // PIMAGE_TLS_CALLBACK *
        [FieldOffset(32)]
        public uint SizeOfZeroFill;
        [FieldOffset(36)]
        public uint Characteristics; // There's more but we don't care about them
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RTLUserProcessParameters
    {
        public uint MaximumLength;
        public uint Length;
        public uint Flags;
        public uint DebugFlags;
        public IntPtr ConsoleHandle;
        public uint ConsoleFlags;
        public IntPtr StdInputHandle;
        public IntPtr StdOutputHandle;
        public IntPtr StdErrorHandle;
        public UnicodeString CurrentDirectoryPath;
        public IntPtr CurrentDirectoryHandle;
        public UnicodeString DllPath;
        public UnicodeString ImagePathname;
        public UnicodeString CommandLine;
        //PVOID Environment;
        //ULONG StartingPositionLeft;
        //ULONG StartingPositionTop;
        //ULONG Width;
        //ULONG Height;
        //ULONG CharWidth;
        //ULONG CharHeight;
        //ULONG ConsoleTextAttributes;
        //ULONG WindowFlags;
        //ULONG ShowWindowFlags;
        //UNICODE_STRING WindowTitle;
        //UNICODE_STRING DesktopName;
        //UNICODE_STRING ShellInfo;
        //UNICODE_STRING RuntimeData;
        //RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct PEB32
    {
        [FieldOffset(0x10)]
        public IntPtr ProcessParameters;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct PEB64
    {
        [FieldOffset(0x20)]
        public IntPtr ProcessParameters;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct RUNTIME_FUNCTION
    {
        [FieldOffset(0)]
        public uint BeginAddress;
        [FieldOffset(4)]
        public uint EndAddress;
        [FieldOffset(8)]
        public uint UnwindInfoAddress;
        [FieldOffset(8)]
        public uint UnwindData;
    }

    public class PEFile
    {
        private byte[] rawBuffer;
        private const uint MzSignature = 0x4d5a;
        private const uint NtSignature = 0x4550;

        public bool Is32 { get; private set; }
        public bool Is64 { get; private set; }
        public ImageDosHeader DosHeader { get; private set; }
        public ImageNtHeaders32 NtHeaders32 { get; private set; }
        public ImageNtHeaders64 NtHeaders64 { get; private set; }
        public IList<ImageSectionHeader> Sections { get; private set; }
        public byte[] Buffer { get { return rawBuffer; } }

        /// <summary>
        /// Forgive me father, for I have sinned.
        /// </summary>
        public dynamic NtHeaders
        {
            get
            {
                if (Is32)
                {
                    return NtHeaders32;
                }
                else
                {
                    return NtHeaders64;
                }
            }
        }

        private PEFile(byte[] buffer)
        {
            rawBuffer = buffer;
            ParseFields();
        }

        private ushort SeekMagic(byte[] buffer)
        {
            ushort ret = 0;

            using (var rdr = new BinaryReader(new MemoryStream(buffer)))
            {
                rdr.BaseStream.Position = 0x3c;
                rdr.BaseStream.Position = rdr.ReadUInt32();
                rdr.BaseStream.Position += 4 + Marshal.SizeOf(typeof(ImageFileHeader));
                ret = rdr.ReadUInt16();
            }

            return ret;
        }

        private bool IsPe64(byte[] buffer)
        {
            return SeekMagic(buffer) == 0x20b;
        }

        private bool IsPe32(byte[] buffer)
        {
            return SeekMagic(buffer) == 0x10b;
        }

        private bool SantiyCheck(byte[] buffer)
        {
            return buffer != null && buffer.Length > 0 && buffer[0] == 0x4d && buffer[1] == 0x5a;
        }

        private void ParseFields()
        {
            Debug.Assert(SantiyCheck(rawBuffer));

            Is32 = IsPe32(rawBuffer);
            Is64 = IsPe64(rawBuffer);

            Debug.Assert(Is32 != Is64);

            GCHandle pinnedBuffer = GCHandle.Alloc(rawBuffer, GCHandleType.Pinned);

            try
            {
                DosHeader = (ImageDosHeader)Marshal.PtrToStructure(pinnedBuffer.AddrOfPinnedObject(), typeof(ImageDosHeader));

                if (Is32)
                {
                    NtHeaders32 = (ImageNtHeaders32)Marshal.PtrToStructure(
                        IntPtr.Add(pinnedBuffer.AddrOfPinnedObject(), (int)DosHeader.e_lfanew),
                        typeof(ImageNtHeaders32));
                }
                else
                {
                    NtHeaders64 = (ImageNtHeaders64)Marshal.PtrToStructure(
                        IntPtr.Add(pinnedBuffer.AddrOfPinnedObject(), (int)DosHeader.e_lfanew),
                        typeof(ImageNtHeaders64));
                }

                Sections = new List<ImageSectionHeader>();

                int fieldOffset = 4 + Marshal.SizeOf(NtHeaders.FileHeader);
                int optionalHdrSize = NtHeaders.FileHeader.SizeOfOptionalHeader;

                var firstSection = (ImageSectionHeader)Marshal.PtrToStructure(
                    IntPtr.Add(pinnedBuffer.AddrOfPinnedObject(), (int)(DosHeader.e_lfanew + fieldOffset + optionalHdrSize)),
                    typeof(ImageSectionHeader));

                Sections.Add(firstSection);

                for (int i = 0; i < NtHeaders.FileHeader.NumberOfSections - 1; i++)
                {
                    var ithSection = (ImageSectionHeader)Marshal.PtrToStructure(
                        IntPtr.Add(pinnedBuffer.AddrOfPinnedObject(), (int)(DosHeader.e_lfanew + fieldOffset + optionalHdrSize + (Sections.Count * Marshal.SizeOf(firstSection)))),
                        typeof(ImageSectionHeader));

                    Sections.Add(ithSection);
                }
            }
            finally
            {
                if (pinnedBuffer.IsAllocated)
                {
                    pinnedBuffer.Free();
                }
            }
        }

        public static PEFile FromBytes(byte[] buffer)
        {
            if (buffer != null && buffer.Length > 0)
            {
                return new PEFile(buffer);
            }

            throw new Exception("Invalid byte array.");
        }
    }
}
