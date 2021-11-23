using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace ExecutePE
{
    public struct PEMapInfo
    {
        public IntPtr RequestedImageBase;
        public IntPtr AllocatedImageBase;
        public bool WasAllocatedAtRequestedBase;
        public IUnmanagedAllocator Allocator;
        public int SizeOfImage;
    }

    public class PEMapper
    {

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr LoadLibraryA(string lpLibFileName);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static unsafe extern IntPtr GetProcAddress(IntPtr hLibrary, char* fnName);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static unsafe extern IntPtr GetProcAddress(IntPtr hLibrary, string fnName);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, ref uint lpflOldProtect);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern bool FlushInstructionCache(IntPtr handle, IntPtr baseaddress, IntPtr size);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern bool GetModuleHandleExW(uint dwFlags, IntPtr lpModuleName, ref IntPtr phModule);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private static extern uint GetModuleFileNameW(IntPtr hModule, StringBuilder lpFileName, uint nSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetCommandLineA();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr GetCommandLineW();

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern bool CloseHandle(IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void PImageTlsCallback(IntPtr DllHandle, uint reason, IntPtr Reserved);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private unsafe delegate int PConsoleMain(int argc, ushort* argv);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int PWinMain(IntPtr hInstance, IntPtr hPrevInstance, string lpCmdLine, int nShowCmd);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool RtlAddFunctionTable(IntPtr functionTable, uint entryCount, IntPtr baseAddress);

        private static bool IsWordSize32()
        {
            if (IntPtr.Size == 4)
            {
                return true;
            }
            else if (IntPtr.Size == 8)
            {
                return false;
            }
            else
            {
                throw new Exception("Unsupported word size.");
            }
        }

        private static bool ImageSnapByOrdinal32(uint ordinal)
        {
            return (ordinal & 0x80000000) != 0;
        }

        private static bool ImageSnapByOrdinal64(ulong ordinal)
        {
            return (ordinal & 0x8000000000000000) != 0;
        }

        private static uint ImageOrdinal32(uint ordinal)
        {
            return (ordinal & 0xffff);
        }

        private static ulong ImageOrdinal64(ulong ordinal)
        {
            return (ordinal & 0xffff);
        }

        private static uint ConvertSectCharToMemProt(uint dwChar)
        {
            // there is def a better way to do this
            uint prot = 0;

            bool exec = (dwChar & 0x20000000) != 0;
            bool read = (dwChar & 0x40000000) != 0;
            bool write = (dwChar & 0x80000000) != 0;

            if (!exec && !read && !write)
            {
                prot = 1;
            }
            else if (!exec && !read && write)
            {
                prot = 8;
            }
            else if (!exec && read && !write)
            {
                prot = 2;
            }
            else if (!exec && read && write)
            {
                prot = 4;
            }
            else if (exec && !read && !write)
            {
                prot = 0x10;
            }
            else if (exec && !read && write)
            {
                prot = 0x80;
            }
            else if (exec && read && !write)
            {
                prot = 0x20;
            }
            else if (exec && read && write)
            {
                prot = 0x40;
            }

            return prot;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr GetPEBAssembly();

        private static IntPtr GetPEB()
        {
            byte[] x86 = { 0x55, 0x89, 0xE5, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x89, 0xEC, 0x5D, 0xC3 };
            byte[] x64 = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xC3 };

            IntPtr hAlloc = IntPtr.Zero;
            IntPtr peb = IntPtr.Zero;
            uint old = 0;

            try
            {
                if (IsWordSize32())
                {
                    hAlloc = Marshal.AllocHGlobal(x86.Length);
                    Marshal.Copy(x86, 0, hAlloc, x86.Length);

                    VirtualProtect(hAlloc, new UIntPtr((uint)x86.Length), 0x40, ref old);

                    var asm86 = (GetPEBAssembly)Marshal.GetDelegateForFunctionPointer(
                        hAlloc,
                        typeof(GetPEBAssembly)
                        );

                    peb = asm86();
                }
                else
                {
                    hAlloc = Marshal.AllocHGlobal(x64.Length);
                    Marshal.Copy(x64, 0, hAlloc, x64.Length);

                    VirtualProtect(hAlloc, new UIntPtr((uint)x64.Length), 0x40, ref old);

                    var asm64 = (GetPEBAssembly)Marshal.GetDelegateForFunctionPointer(
                        hAlloc,
                        typeof(GetPEBAssembly)
                        );

                    peb = asm64();
                }
            }
            finally
            {
                if (hAlloc != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(hAlloc);
                }
            }

            return peb;
        }

        private static unsafe void PatchCommandLine(string newCommandLine, out string oldCommandLine, out IList<IntPtr> allocatedStrings)
        {
            allocatedStrings = new List<IntPtr>();
            oldCommandLine = Marshal.PtrToStringUni(GetCommandLineW());

            byte* fnGetCommandLineA = (byte*)GetProcAddress(LoadLibraryA("kernel32.dll"), "GetCommandLineA");
            byte* fnGetCommandLineW = (byte*)GetProcAddress(LoadLibraryA("kernel32.dll"), "GetCommandLineW");

            if (IsWordSize32())
            {
                if (*fnGetCommandLineA == 0xff && *(fnGetCommandLineA + 1) == 0x25)
                {
                    byte* new_addr = (byte*)**(uint**)(fnGetCommandLineA + 2);

                    if (*new_addr == 0xa1)
                    {
                        char* read_addr = (char*)(new_addr + 1);
                        char* deref_that_read = (char*)*(uint*)read_addr;
                        char* another_deref = (char*)*(uint*)deref_that_read;

                        IntPtr strA = Marshal.StringToHGlobalAnsi(newCommandLine);
                        allocatedStrings.Add(strA);
                        *(uint*)deref_that_read = (uint)strA;

                        Debug.Assert(Marshal.PtrToStringAnsi(GetCommandLineA()) == newCommandLine);
                    }
                }

                if (*fnGetCommandLineW == 0xff && *(fnGetCommandLineW + 1) == 0x25)
                {
                    byte* new_addr = (byte*)**(uint**)(fnGetCommandLineW + 2);

                    if (*new_addr == 0xa1)
                    {
                        char* read_addr = (char*)(new_addr + 1);
                        char* deref_that_read = (char*)*(uint*)read_addr;
                        char* another_deref = (char*)*(uint*)deref_that_read;

                        IntPtr strW = Marshal.StringToHGlobalUni(newCommandLine);
                        allocatedStrings.Add(strW);
                        *(uint*)deref_that_read = (uint)strW;

                        Debug.Assert(Marshal.PtrToStringUni(GetCommandLineW()) == newCommandLine);
                    }
                }
            }
            else
            {
                if (*fnGetCommandLineA == 0x48 && *(fnGetCommandLineA + 1) == 0xff)
                {
                    uint jmp_addr = *(uint*)(fnGetCommandLineA + 3);
                    byte* new_addr = (fnGetCommandLineA + jmp_addr + 7);
                    byte* mov_rax = (byte*)*(ulong*)new_addr;

                    if (*mov_rax == 0x48 && *(mov_rax + 1) == 0x8b && *(mov_rax + 2) == 0x05)
                    {
                        uint rel_addr = *(uint*)(mov_rax + 3);
                        char* read_addr = (char*)(mov_rax + rel_addr + 7);
                        char* deref_ansi_basecommandline = (char*)*(ulong*)read_addr;

                        IntPtr strA = Marshal.StringToHGlobalAnsi(newCommandLine);
                        allocatedStrings.Add(strA);
                        *(ulong*)read_addr = (ulong)strA;

                        Debug.Assert(Marshal.PtrToStringAnsi(GetCommandLineA()) == newCommandLine);
                    }
                }

                if (*fnGetCommandLineW == 0x48 && *(fnGetCommandLineW + 1) == 0xff)
                {
                    uint jmp_addr = *(uint*)(fnGetCommandLineW + 3);
                    byte* new_addr = (fnGetCommandLineW + jmp_addr + 7);

                    byte* mov_rax = (byte*)*(ulong*)new_addr;

                    if (*mov_rax == 0x48 && *(mov_rax + 1) == 0x8b && *(mov_rax + 2) == 0x05)
                    {
                        uint rel_addr = *(uint*)(mov_rax + 3);
                        char* read_addr = (char*)(mov_rax + rel_addr + 7);
                        ushort* deref_unicode_basecommandline = (ushort*)*(ulong*)read_addr;

                        IntPtr strW = Marshal.StringToHGlobalUni(newCommandLine);
                        allocatedStrings.Add(strW);
                        *(ulong*)read_addr = (ulong)strW;

                        Debug.Assert(Marshal.PtrToStringUni(GetCommandLineW()) == newCommandLine);
                    }
                }
            }

            // crt patch
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (module.ModuleName.ToUpper().Contains("MSVCR"))
                {
                    if (IsWordSize32())
                    {
                        // these are just a pointer to a char/wchar_t pointer
                        byte* fnA = (byte*)GetProcAddress(module.BaseAddress, "_acmdln");
                        byte* fnW = (byte*)GetProcAddress(module.BaseAddress, "_wcmdln");

                        if (fnA != null && fnW != null)
                        {
                            uint ptr_read_A = *(uint*)fnA;
                            uint ptr_read_W = *(uint*)fnW;

                            string commandLineA = Marshal.PtrToStringAnsi(new IntPtr((void*)ptr_read_A));
                            string commandLineW = Marshal.PtrToStringUni(new IntPtr((void*)ptr_read_W));

                            IntPtr strA = Marshal.StringToHGlobalAnsi(newCommandLine);
                            IntPtr strW = Marshal.StringToHGlobalUni(newCommandLine);

                            allocatedStrings.Add(strA);
                            allocatedStrings.Add(strW);

                            *(uint*)fnA = (uint)strA;
                            *(uint*)fnW = (uint)strW;

                            commandLineA = Marshal.PtrToStringAnsi(new IntPtr((void*)*(uint*)fnA));
                            commandLineW = Marshal.PtrToStringUni(new IntPtr((void*)*(uint*)fnW));
                        }
                    }
                    else
                    {
                        byte* fnA = (byte*)GetProcAddress(module.BaseAddress, "_acmdln");
                        byte* fnW = (byte*)GetProcAddress(module.BaseAddress, "_wcmdln");

                        if (fnA != null && fnW != null)
                        {
                            ulong ptr_read_A = *(ulong*)fnA;
                            ulong ptr_read_W = *(ulong*)fnW;

                            string commandLineA = Marshal.PtrToStringAnsi(new IntPtr((void*)ptr_read_A));
                            string commandLineW = Marshal.PtrToStringUni(new IntPtr((void*)ptr_read_W));

                            IntPtr strA = Marshal.StringToHGlobalAnsi(newCommandLine);
                            IntPtr strW = Marshal.StringToHGlobalUni(newCommandLine);

                            allocatedStrings.Add(strA);
                            allocatedStrings.Add(strW);

                            *(ulong*)fnA = (ulong)strA;
                            *(ulong*)fnW = (ulong)strW;

                            commandLineA = Marshal.PtrToStringAnsi(new IntPtr((void*)*(ulong*)fnA));
                            commandLineW = Marshal.PtrToStringUni(new IntPtr((void*)*(ulong*)fnW));
                        }
                    }
                }
            }
        }

        public unsafe static void MapImageInternal(PEFile pe, string commandLine)
        {
            // mapInfo
            // mapOptions

            if (pe.Is32 && !IsWordSize32())
            {
                throw new BadImageFormatException("Image bitness mismatch.");
            }

            if (pe.Is64 && IsWordSize32())
            {
                throw new BadImageFormatException("Image bitness mismatch.");
            }

            var mapInfo = new PEMapInfo()
            {
                Allocator = new VirtualAllocAllocator(),
                RequestedImageBase = (IntPtr)pe.NtHeaders.OptionalHeader.ImageBase,
                SizeOfImage = (int)pe.NtHeaders.OptionalHeader.SizeOfImage
            };

            // Allocate unmanaged memory chunk
            var allocStatus = mapInfo.Allocator.Allocate(ref mapInfo);

            if (allocStatus != UnmanagedAllocationResult.Success)
            {
                throw new Exception("Could not allocate memory.");
            }

            // Copy headers and sections into memory
            Marshal.Copy(pe.Buffer, 0, mapInfo.AllocatedImageBase, (int)pe.NtHeaders.OptionalHeader.SizeOfHeaders);

            foreach (var section in pe.Sections)
            {
                // ToDo: Handle edge cases with packed PE files
                // Don't copy anything if SizeOfRawData is 0. You can have 2 sections with same PointerToRawData and if you copy any data, you risk having invalid initial state for the first of those 2 sections.
                // SizeOfImage includes VirtualSize each section, even if SizeOfRawData is 0.
                var sectionWriteAddress = mapInfo.AllocatedImageBase.Add(section.VirtualAddress);
                Marshal.Copy(pe.Buffer, (int)section.PointerToRawData, sectionWriteAddress, (int)section.SizeOfRawData);
            }

            // Relocate our image if necessary
            if (!mapInfo.WasAllocatedAtRequestedBase)
            {
                ImageDataDirectory relocDataDir = pe.NtHeaders.OptionalHeader.RelocationDirectory;

                if (relocDataDir.Size == 0)
                {
                    throw new Exception("Cannot map a file without relocation table at an address other than it's preferred imagebase.");
                }

                IntPtr relocDelta = mapInfo.AllocatedImageBase.Sub((IntPtr)pe.NtHeaders.OptionalHeader.ImageBase);
                IntPtr relocTablePtr = mapInfo.AllocatedImageBase.Add(relocDataDir.VirtualAddress);

                // Here's where I got tired of using safe code lol
                ImageBaseRelocation* relocation = (ImageBaseRelocation*)relocTablePtr;

                while (relocation->VirtualAddress != 0)
                {
                    ushort* relocList = (ushort*)(relocation + 1);

                    while (relocList != ((byte*)relocation + relocation->SizeOfBlock))
                    {
                        ushort relocType = (ushort)((*relocList) >> 12);
                        ushort relocOffset = (ushort)((*relocList) & 0xfff);

                        switch (relocType)
                        {
                            case 0xA:
                                IntPtr* rwAddress = (IntPtr*)((byte*)mapInfo.AllocatedImageBase + relocation->VirtualAddress + relocOffset);
                                IntPtr unRelocatedValue = *rwAddress;
                                *rwAddress = unRelocatedValue.Add(relocDelta);
                                break;
                            default:
                                break;
                        }

                        relocList++;
                    }

                    relocation = (ImageBaseRelocation*)relocList;
                }
            }

            // Process import table
            // ToDo: Process delayed imports
            ImageDataDirectory importDataDir = pe.NtHeaders.OptionalHeader.ImportDirectory;

            if (importDataDir.Size != 0 && importDataDir.VirtualAddress != 0)
            {
                ImageImportDescriptor* descriptor = (ImageImportDescriptor*)mapInfo.AllocatedImageBase.Add(importDataDir.VirtualAddress);

                while (descriptor->Name != 0)
                {
                    string libraryName = Marshal.PtrToStringAnsi(mapInfo.AllocatedImageBase.Add(descriptor->Name));

                    IntPtr hLibrary = LoadLibraryA(libraryName);

                    if (hLibrary != IntPtr.Zero)
                    {
                        if (IsWordSize32())
                        {
                            ImageThunkData32* firstDon = (ImageThunkData32*)mapInfo.AllocatedImageBase.Add(descriptor->FirstThunk);
                            ImageThunkData32* originalDon = (ImageThunkData32*)mapInfo.AllocatedImageBase.Add(descriptor->OriginalFirstThunk);

                            while (originalDon->Function != 0)
                            {
                                if (ImageSnapByOrdinal32(originalDon->Ordinal))
                                {
                                    firstDon->Function = (uint)GetProcAddress(hLibrary, (char*)ImageOrdinal32(originalDon->Ordinal)).ToInt32();
                                }
                                else
                                {
                                    ImageImportByName* namedImport = (ImageImportByName*)mapInfo.AllocatedImageBase.Add(originalDon->AddressOfData);
                                    // Console.WriteLine($"Library: {libraryName}\tFunction: {Marshal.PtrToStringAnsi((IntPtr)namedImport->Name)}");
                                    firstDon->Function = (uint)GetProcAddress(hLibrary, namedImport->Name).ToInt32();

                                    if (libraryName.ToUpper() == "KERNEL32.DLL")
                                    {
                                        string function_name = Marshal.PtrToStringAnsi((IntPtr)namedImport->Name);

                                        if (function_name == "ExitProcess")
                                        {
                                            // Change all calls to exitprocess to exitthread
                                            // They have same number of args and the args don't affect the call
                                            // ez
                                            firstDon->Function = (uint)GetProcAddress(hLibrary, "ExitThread");
                                        }
                                    }
                                }

                                firstDon++;
                                originalDon++;
                            }
                        }
                        else
                        {
                            ImageThunkData64* firstDon = (ImageThunkData64*)mapInfo.AllocatedImageBase.Add(descriptor->FirstThunk);
                            ImageThunkData64* originalDon = (ImageThunkData64*)mapInfo.AllocatedImageBase.Add(descriptor->OriginalFirstThunk);

                            while (originalDon->Function != 0)
                            {
                                if (ImageSnapByOrdinal64(originalDon->Ordinal))
                                {
                                    firstDon->Function = (ulong)GetProcAddress(hLibrary, (char*)ImageOrdinal64(originalDon->Ordinal)).ToInt64();
                                    //  Debugger.Break();
                                }
                                else
                                {
                                    ImageImportByName* namedImport = (ImageImportByName*)mapInfo.AllocatedImageBase.Add(originalDon->AddressOfData);
                                    // Console.WriteLine($"Library: {libraryName}\tFunction: {Marshal.PtrToStringAnsi((IntPtr)namedImport->Name)}");
                                    firstDon->Function = (ulong)GetProcAddress(hLibrary, namedImport->Name).ToInt64();

                                    if (libraryName.ToUpper() == "KERNEL32.DLL")
                                    {
                                        string function_name = Marshal.PtrToStringAnsi((IntPtr)namedImport->Name);

                                        if (function_name == "ExitProcess")
                                        {
                                            // Change all calls to exitprocess to exitthread
                                            // They have same number of args and the args don't affect the call
                                            // ez
                                            firstDon->Function = (ulong)GetProcAddress(hLibrary, "ExitThread").ToInt64();
                                        }
                                    }
                                }

                                firstDon++;
                                originalDon++;
                            }
                        }
                    }
                    else
                    {
                        throw new Exception($"Failed to load {libraryName}");
                    }

                    descriptor++;
                }
            }

            // Set memory protections
            uint refOld = 0;
            VirtualProtect(mapInfo.AllocatedImageBase, new UIntPtr((uint)pe.NtHeaders.OptionalHeader.SizeOfHeaders), 0x02, ref refOld);

            //IntPtr entrypoint = mapInfo.AllocatedImageBase.Add((uint)pe.NtHeaders.OptionalHeader.AddressOfEntryPoint);
            //*(byte*)entrypoint = 0xcc;

            // so loader is allocate(VirtualSize + SectionAlignment - 1) & ~(SectionAlignment - 1) bytes for section
            // copy min(VirtualSize, SizeOfRawData) bytes to it from file
            foreach (var section in pe.Sections)
            {
                IntPtr addrProtecc = mapInfo.AllocatedImageBase.Add(section.VirtualAddress);
                UIntPtr sizeProtecc = new UIntPtr(section.Misc.VirtualSize);

                uint dwProtecc = ConvertSectCharToMemProt(section.Characteristics);
                VirtualProtect(addrProtecc, sizeProtecc, dwProtecc, ref refOld);
            }

            FlushInstructionCache((IntPtr)(-1), IntPtr.Zero, IntPtr.Zero);

            // ok, TLS static data (yet) is not gonna be set but I think that's OK for most EXEs
            ImageDataDirectory tlsDataDir = pe.NtHeaders.OptionalHeader.TlsDirectory;

            if (tlsDataDir.Size != 0 && tlsDataDir.VirtualAddress != 0)
            {
                if (IsWordSize32())
                {
                    ImageTlsDirectory32* tlsDirectory32 = (ImageTlsDirectory32*)mapInfo.AllocatedImageBase.Add(tlsDataDir.VirtualAddress);
                    uint* tlsCallbackItr = (uint*)tlsDirectory32->AddressOfCallBacks;

                    while (*tlsCallbackItr != 0)
                    {
                        var callback = (PImageTlsCallback)Marshal.GetDelegateForFunctionPointer(
                            new IntPtr(*tlsCallbackItr),
                            typeof(PImageTlsCallback)
                            );

                        callback(mapInfo.AllocatedImageBase, 1, IntPtr.Zero);
                    }
                }
                else
                {
                    ImageTlsDirectory64* tlsDirectory64 = (ImageTlsDirectory64*)mapInfo.AllocatedImageBase.Add(tlsDataDir.VirtualAddress);
                    ulong* tlsCallbackItr = (ulong*)tlsDirectory64->AddressOfCallBacks;

                    while (*tlsCallbackItr != 0)
                    {
                        var callback = (PImageTlsCallback)Marshal.GetDelegateForFunctionPointer(
                            new IntPtr((void*)*tlsCallbackItr),
                            typeof(PImageTlsCallback)
                            );

                        callback(mapInfo.AllocatedImageBase, 1, IntPtr.Zero);
                    }
                }
            }

            if (!IsWordSize32())
            {
                ImageDataDirectory exceptionDir = pe.NtHeaders.OptionalHeader.ExceptionDirectory;

                if (exceptionDir.Size > 0)
                {
                    IntPtr ptrAddFunctionTable = GetProcAddress(LoadLibraryA("Kernel32.dll"), "RtlAddFunctionTable");

                    if (ptrAddFunctionTable != IntPtr.Zero)
                    {
                        var rtlAddFunctionTable = (RtlAddFunctionTable)Marshal.GetDelegateForFunctionPointer(ptrAddFunctionTable, typeof(RtlAddFunctionTable));

                        RUNTIME_FUNCTION* functionTable = (RUNTIME_FUNCTION*)mapInfo.AllocatedImageBase.Add(exceptionDir.VirtualAddress);
                        uint count = (uint)(exceptionDir.Size / Marshal.SizeOf(typeof(RUNTIME_FUNCTION)));
                        rtlAddFunctionTable((IntPtr)functionTable, count, mapInfo.AllocatedImageBase);
                    }
                }
            }



            // let's set our command line
            string oldCommandLine = string.Empty;
            string discardCommandLine = string.Empty;
            IList<IntPtr> allocatedStrings;
            PatchCommandLine($"\"{System.Reflection.Assembly.GetExecutingAssembly().Location}\" " + commandLine, out oldCommandLine, out allocatedStrings);

            //string haxxA = Marshal.PtrToStringAnsi(GetCommandLineA());
            //string haxxW = Marshal.PtrToStringUni(GetCommandLineW());
            //var haxx = Environment.GetCommandLineArgs();
            //Debugger.Break();

            // Determine what type of pe we are
            var subsystem = pe.NtHeaders.OptionalHeader.Subsystem;
            var fileHdrChars = pe.NtHeaders.FileHeader.Characteristics;
            IntPtr entrypoint = mapInfo.AllocatedImageBase.Add((uint)pe.NtHeaders.OptionalHeader.AddressOfEntryPoint);

            if (subsystem == 3)
            {
                // we are console or dll
                if ((fileHdrChars & 0x0002) != 0)
                {
                    // we are a console exe

                    //PConsoleMain consoleMain = (PConsoleMain)Marshal.GetDelegateForFunctionPointer(
                    //    entrypoint,
                    //    typeof(PConsoleMain)
                    //    );

                    uint dwThreadId = 0;
                    IntPtr hThread = CreateThread(IntPtr.Zero, UIntPtr.Zero, entrypoint, IntPtr.Zero, 0, ref dwThreadId);
                    WaitForSingleObject(hThread, 0xffffffff);
                    CloseHandle(hThread);

                    allocatedStrings.ToList().ForEach(S => Marshal.FreeHGlobal(S));
                    allocatedStrings.Clear();
                    PatchCommandLine(oldCommandLine, out discardCommandLine, out allocatedStrings);
                    var test = Environment.GetCommandLineArgs();

                    //while ((argc > 1) && (argv[1][0] == '-'))
                    //ushort* args = (ushort*)Marshal.StringToHGlobalUni(System.Reflection.Assembly.GetExecutingAssembly().Location + " -h");
                    //consoleMain(1, args);

                    // consoleMain(1, new string[] { "-h" });
                    // consoleMain(2, new string[] { "-h", "-h " });

                    //Debugger.Break();
                }

                if ((fileHdrChars & 0x2000) != 0)
                {
                    // we are a dll
                }
            }
            else if (subsystem == 2)
            {
                // we are gui application

                PWinMain winMain = (PWinMain)Marshal.GetDelegateForFunctionPointer(
                    entrypoint,
                    typeof(PWinMain)
                    );

                winMain(mapInfo.AllocatedImageBase, IntPtr.Zero, string.Empty, 0);
            }
            else
            {
                throw new Exception($"Unsupported subsystem of value {subsystem}.");
            }
        }
    }
}
