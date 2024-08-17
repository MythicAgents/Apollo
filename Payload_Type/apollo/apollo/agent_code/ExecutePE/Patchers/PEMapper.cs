using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using ExecutePE.Helpers;
using ExecutePE.Internals;

namespace ExecutePE.Patchers
{
    internal class PEMapper
    {
        private IntPtr _codebase;
        private PELoader? _pe;

        public void MapPEIntoMemory(byte[] unpacked, out PELoader peLoader, out long currentBase)
        {
            _pe = peLoader = new PELoader(unpacked);
            _codebase = NativeDeclarations.VirtualAlloc(IntPtr.Zero, _pe.OptionalHeader64.SizeOfImage,
                NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
            currentBase = _codebase.ToInt64();

            int relocTableFileOffset = 0;
            int relocTableFileSize = 0;

            // Copy Sections
            for (var i = 0; i < _pe.FileHeader.NumberOfSections; i++)
            {
                // The relocation table is typically marked as 'SCN_MEM_DISCARDABLE' so it will be discarded.
                // Check if this section refers to the relocation table and save the file offset.
                // The relocations are parsed from the file and not the virtual address.
                if (_pe.OptionalHeader64.BaseRelocationTable.VirtualAddress == _pe.ImageSectionHeaders[i].VirtualAddress)
                {
                    try
                    {
                        checked
                        {
                            relocTableFileOffset = (int)_pe.ImageSectionHeaders[i].PointerToRawData;
                        }
                    }
                    catch (OverflowException)
                    {
                        throw new InvalidOperationException("Relocation table file offset is invalid");
                    }

                    try
                    {
                        checked
                        {
                            relocTableFileSize = (int)_pe.ImageSectionHeaders[i].SizeOfRawData;
                        }
                    }
                    catch (OverflowException)
                    {
                        throw new InvalidOperationException("Relocation table size is invalid");
                    }
                }

                // Discard sections marked as discardable
                if (_pe.ImageSectionHeaders[i].Characteristics.HasFlag(PELoader.SectionFlags.IMAGE_SCN_MEM_DISCARDABLE))
                {
                    continue;
                }

                var sectionSize = (
                    _pe.ImageSectionHeaders[i].SizeOfRawData > _pe.ImageSectionHeaders[i].VirtualSize
                    ? _pe.ImageSectionHeaders[i].SizeOfRawData
                    : _pe.ImageSectionHeaders[i].VirtualSize
                );

                var y = NativeDeclarations.VirtualAlloc((IntPtr)(currentBase + _pe.ImageSectionHeaders[i].VirtualAddress),
                    sectionSize, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
                if (y == null)
                {
                    var sectionName = new string(_pe.ImageSectionHeaders[i].Name);
                    var exc = new Win32Exception();
                    throw new Exception($"Could not allocate memory for the '{sectionName}' section: {exc.Message}");
                }

                // Copy the section data if the section has initialized data or code
                if (_pe.ImageSectionHeaders[i].Characteristics.HasFlag(PELoader.SectionFlags.IMAGE_SCN_CNT_INITIALIZED_DATA)
                    || _pe.ImageSectionHeaders[i].Characteristics.HasFlag(PELoader.SectionFlags.IMAGE_SCN_CNT_CODE))
                {
                    Marshal.Copy(_pe.RawBytes, (int)_pe.ImageSectionHeaders[i].PointerToRawData, y, (int)_pe.ImageSectionHeaders[i].SizeOfRawData);
                }
            }

            // Calculate the delta for relocations
            var delta = currentBase - (long)_pe.OptionalHeader64.ImageBase;

            // Get the start of the relocation table from the file offset. Assume that a non-existent
            // relocation table means that the PE is malformed.
            if (relocTableFileOffset == 0)
            {
                throw new InvalidOperationException("Relocation table not found. PE may be malformed.");
            }

            var relocationTable = unpacked.AsSpan(relocTableFileOffset, relocTableFileSize);
            var relocationIndex = 0;

            var baseRelocationEntry = NativeDeclarations.IMAGE_BASE_RELOCATION.Parse(relocationTable[relocationIndex..].ToArray());
            var baseRelocationBlockSize = 8;

            // Iterate over each entry in the relocation table and apply relocations
            while (baseRelocationEntry.SizeOfBlock != 0)
            {
                IntPtr relocationBaseAddress = (IntPtr)(currentBase + baseRelocationEntry.VirtualAddress);

                var relocationEntriesStart = relocationIndex + baseRelocationBlockSize;
                var relocationEntriesByteCount = baseRelocationEntry.SizeOfBlock - baseRelocationBlockSize;

                var relocationEntries = relocationTable.Slice(relocationEntriesStart, (int)relocationEntriesByteCount);
                for (var offset = 0; offset < relocationEntries.Length; offset += 2)
                {
                    var relocEntry = BitConverter.ToUInt16(relocationEntries.ToArray(), offset);
                    var relocType = (byte)((ushort)(relocEntry & 0xf000) >> 12);
                    var patchAddress = relocationBaseAddress.Add(relocEntry & 0xfff);

                    switch (relocType)
                    {
                        case (byte)NativeDeclarations.X86BaseRelocationType.IMAGE_REL_BASED_ABSOLUTE:
                            break;

                        case (byte)NativeDeclarations.X86BaseRelocationType.IMAGE_REL_BASED_HIGH:
                            var addressValue = (uint)Marshal.ReadInt32(patchAddress);
                            var highValue = ((delta >> 16) + (addressValue >> 16)) << 16;
                            Marshal.WriteInt32(patchAddress, (int)(highValue | (addressValue & 0xffff)));
                            break;

                        case (byte)NativeDeclarations.X86BaseRelocationType.IMAGE_REL_BASED_LOW:
                            addressValue = (uint)Marshal.ReadInt32(patchAddress);
                            var lowValue = (delta & 0xffff) + (addressValue & 0xffff);
                            Marshal.WriteInt32(patchAddress, (int)((addressValue & ~0xffff) | lowValue));
                            break;

                        case (byte)NativeDeclarations.X86BaseRelocationType.IMAGE_REL_BASED_HIGHLOW:
                            addressValue = (uint)Marshal.ReadInt32(patchAddress);
                            Marshal.WriteInt32(patchAddress, (int)(addressValue + delta));
                            break;

                        case (byte)NativeDeclarations.X86BaseRelocationType.IMAGE_REL_BASED_DIR64:
                            var originalAddr = Marshal.ReadInt64(patchAddress);
                            Marshal.WriteInt64(patchAddress, originalAddr + delta);
                            break;

                        default:
                            throw new InvalidOperationException($"Found an invalid relocation type {relocType}");
                    }
                }

                relocationIndex += (int)baseRelocationEntry.SizeOfBlock;
                baseRelocationEntry = NativeDeclarations.IMAGE_BASE_RELOCATION.Parse(relocationTable[relocationIndex..].ToArray());
            }
        }

        internal void ClearPE()
        {
            var size = _pe?.OptionalHeader64.SizeOfImage;
            if (size != null)
            {
                Utils.ZeroOutMemory(_codebase, (int)size);
            }

            Utils.FreeMemory(_codebase);
        }

        internal void SetPagePermissions()
        {
            for (var i = 0; i < _pe?.FileHeader.NumberOfSections; i++)
            {
                // Skip over discarded sections since they are not mapped in
                if (_pe.ImageSectionHeaders[i].Characteristics.HasFlag(PELoader.SectionFlags.IMAGE_SCN_MEM_DISCARDABLE))
                {
                    continue;
                }

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

                NativeDeclarations.VirtualProtect((IntPtr)(_codebase.ToInt64() + _pe.ImageSectionHeaders[i].VirtualAddress),
                    (UIntPtr)_pe.ImageSectionHeaders[i].SizeOfRawData, protection, out _);
            }
        }
    }
}
