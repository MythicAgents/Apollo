using System;
using System.Runtime.InteropServices;
using ExecutePE.Helpers;
using ExecutePE.Internals;

namespace ExecutePE.Patchers
{
    internal class PEMapper
    {
        private IntPtr _codebase;
        private PELoader _pe;

        public void MapPEIntoMemory(byte[] unpacked, out PELoader peLoader, out long currentBase)
        {
#if DEBUG


#endif
            _pe = peLoader = new PELoader(unpacked);
            _codebase = NativeDeclarations.VirtualAlloc(IntPtr.Zero, _pe.OptionalHeader64.SizeOfImage,
                NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
            currentBase = _codebase.ToInt64();
#if DEBUG


#endif

            // Copy Sections
            for (var i = 0; i < _pe.FileHeader.NumberOfSections; i++)
            {
                var y = NativeDeclarations.VirtualAlloc((IntPtr)(currentBase + _pe.ImageSectionHeaders[i].VirtualAddress),
                    _pe.ImageSectionHeaders[i].SizeOfRawData, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
                Marshal.Copy(_pe.RawBytes, (int)_pe.ImageSectionHeaders[i].PointerToRawData, y, (int)_pe.ImageSectionHeaders[i].SizeOfRawData);
            }

            // Perform Base Relocation
            var delta = currentBase - (long)_pe.OptionalHeader64.ImageBase;

            // Modify Memory Based On Relocation Table
            var relocationTable =
                (IntPtr)(currentBase + (int)_pe.OptionalHeader64.BaseRelocationTable.VirtualAddress);
            var relocationEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(relocationTable, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));

            var imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));
            var nextEntry = relocationTable;
            var sizeofNextBlock = (int)relocationEntry.SizeOfBlock;
            var offset = relocationTable;

            while (true)
            {
                var pRelocationTableNextBlock = (IntPtr)(relocationTable.ToInt64() + sizeofNextBlock);

                var relocationNextEntry =
                    (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(pRelocationTableNextBlock, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));

                var pRelocationEntry = (IntPtr)(currentBase + relocationEntry.VirtualAdress);

                for (var i = 0; i < (int)((relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++) // TODO figure out magic numbers
                {
                    var value = (ushort)Marshal.ReadInt16(offset, 8 + 2 * i); // TODO figure out magic numbers
                    var type = (ushort)(value >> 12); // TODO figure out magic numbers
                    var fixup = (ushort)(value & 0xfff); // TODO figure out magic numbers

                    switch (type)
                    {
                        case 0x0:
                            break;
                        case 0xA:
                            var patchAddress = (IntPtr)(pRelocationEntry.ToInt64() + fixup);
                            var originalAddr = Marshal.ReadInt64(patchAddress);
                            Marshal.WriteInt64(patchAddress, originalAddr + delta);
                            break;
                    }
                }

                offset = (IntPtr)(relocationTable.ToInt64() + sizeofNextBlock);
                sizeofNextBlock += (int)relocationNextEntry.SizeOfBlock;
                relocationEntry = relocationNextEntry;
                nextEntry = (IntPtr)(nextEntry.ToInt64() + sizeofNextBlock);

                if (relocationNextEntry.SizeOfBlock == 0)
                {
#if DEBUG


#endif
                    break;
                }
            }

#if DEBUG




#endif
        }

        internal void ClearPE()
        {
            var size = _pe.OptionalHeader64.SizeOfImage;
#if DEBUG


#endif
            Utils.ZeroOutMemory(_codebase, (int)size);
            Utils.FreeMemory(_codebase);

#if DEBUG


#endif
        }

        internal void SetPagePermissions()
        {
            for (var i = 0; i < _pe.FileHeader.NumberOfSections; i++)
            {
                var execute = ((uint)_pe.ImageSectionHeaders[i].Characteristics & NativeDeclarations.IMAGE_SCN_MEM_EXECUTE) != 0;
                var read = ((uint)_pe.ImageSectionHeaders[i].Characteristics & NativeDeclarations.IMAGE_SCN_MEM_READ) != 0;
                var write = ((uint)_pe.ImageSectionHeaders[i].Characteristics & NativeDeclarations.IMAGE_SCN_MEM_WRITE) != 0;

                var protection = NativeDeclarations.PAGE_EXECUTE_READWRITE;

                if (execute && read && write)
                {
                    protection = NativeDeclarations.PAGE_EXECUTE_READWRITE;
                }
                else if (!execute && read && write)
                {
                    protection = NativeDeclarations.PAGE_READWRITE;
                }
                else if (!write && execute && read)
                {
                    protection = NativeDeclarations.PAGE_EXECUTE_READ;
                }
                else if (!execute && !write && read)
                {
                    protection = NativeDeclarations.PAGE_READONLY;
                }
                else if (execute && !read && !write)
                {
                    protection = NativeDeclarations.PAGE_EXECUTE;
                }
                else if (!execute && !read && !write)
                {
                    protection = NativeDeclarations.PAGE_NOACCESS;
                }

                var y = NativeDeclarations.VirtualProtect((IntPtr)(_codebase.ToInt64() + _pe.ImageSectionHeaders[i].VirtualAddress),
                    (UIntPtr)_pe.ImageSectionHeaders[i].SizeOfRawData, protection, out _);
            }
        }
    }
}