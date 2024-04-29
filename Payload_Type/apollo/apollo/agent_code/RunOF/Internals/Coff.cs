using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;

namespace RunOF.Internals
{
    class Coff
    {
        private IMAGE_FILE_HEADER file_header;
        private List<IMAGE_SECTION_HEADER> section_headers;
        private List<IMAGE_SYMBOL> symbols;
        private long string_table;
        internal IntPtr base_addr;
        internal int size;
        private MemoryStream stream;
        private BinaryReader reader;
        private ARCH MyArch;
        private ARCH BofArch;
        private string ImportPrefix;
        private string HelperPrefix;
        private string EntryWrapperSymbol = "go_wrapper";
        private string EntrySymbol = "go";
        private List<Permissions> permissions = new List<Permissions>();
        //private IntPtr iat;
        private IAT iat;
        public IntPtr global_buffer { get; private set; }
        public IntPtr global_buffer_size_ptr {get; private set;}
        public int global_buffer_size { get; set; } = 1024;
        public IntPtr argument_buffer { get; private set; }
        public int argument_buffer_size { get; set; }
        private string InternalDLLName { get; set; } = "RunOF";

        private enum ARCH: int 
        {
            I386 = 0,
            AMD64 = 1
        }

        public Coff(byte[] file_contents, IAT iat)
        {
            try
            {
                Logger.Debug($"--- Loading object file from byte array ---");

                if (iat != null)
                {
                    this.iat = iat;
                }
                else
                {
                    this.iat = new IAT();
                }

                this.MyArch = Environment.Is64BitProcess ? ARCH.AMD64 : ARCH.I386;

                // do some field setup
                this.stream = new MemoryStream(file_contents);
                this.reader = new BinaryReader(this.stream);

                this.section_headers = new List<IMAGE_SECTION_HEADER>();
                this.symbols = new List<IMAGE_SYMBOL>();

                // Allocate some memory, for now just the whole size of the object file. 
                // TODO - could just do the memory for the sections and not the header?
                // TODO - memory permissions


                // copy across
                //Marshal.Copy(file_contents, 0, base_addr, file_contents.Length);

                // setup some objects to help us understand the file
                this.file_header = Deserialize<IMAGE_FILE_HEADER>(file_contents);

                // check the architecture
                Logger.Debug($"Got file header. Architecture {this.file_header.Machine}");

                if (!ArchitectureCheck())
                {
                    Logger.Error($"Object file architecture {this.BofArch} does not match process architecture {this.MyArch}");
                    throw new NotImplementedException();
                }

                // Compilers use different prefixes to symbols depending on architecture. 
                // There might be other naming conventions for functions imported in different ways, but I'm not sure.
                if (this.BofArch == ARCH.I386)
                {
                    this.ImportPrefix = "__imp__";
                    this.HelperPrefix = "_"; // This I think means a global function
                }
                else if (this.BofArch == ARCH.AMD64)
                {
                    this.ImportPrefix = "__imp_";
                    this.HelperPrefix = String.Empty;
                }

                if (this.file_header.SizeOfOptionalHeader != 0)
                {
                    Logger.Error($"[x] Bad object file: has an optional header??");
                    throw new Exception("Object file had an optional header, not standards-conforming");
                }

                // Setup our section header list.
                Logger.Debug($"Parsing {this.file_header.NumberOfSections} section headers");
                FindSections();

                Logger.Debug($"Parsing {this.file_header.NumberOfSymbols} symbols");
                FindSymbols();

                // The string table has specified offset, it's just located directly after the last symbol header - so offset is sym_table_offset + (num_symbols * sizeof(symbol))
                Logger.Debug($"Setting string table offset to 0x{(this.file_header.NumberOfSymbols * Marshal.SizeOf(typeof(IMAGE_SYMBOL))) + this.file_header.PointerToSymbolTable:X}");
                this.string_table = (this.file_header.NumberOfSymbols * Marshal.SizeOf(typeof(IMAGE_SYMBOL))) + this.file_header.PointerToSymbolTable;

                // We allocate and copy the file into memory once we've parsed all our section and string information
                // This is so we can use the section information to only map the stuff we need

                //size = (uint)file_contents.Length;

                // because we need to page align our sections, the overall size may be larger than the filesize
                // calculate our overall size here
                int total_pages = 0;
                foreach (var section_header in this.section_headers)
                {
                    int section_pages = (int)section_header.SizeOfRawData / Environment.SystemPageSize;
                    if (section_header.SizeOfRawData % Environment.SystemPageSize != 0)
                    {
                        section_pages++;
                    }

                    total_pages = total_pages + section_pages;
                }

                Logger.Debug($"We need to allocate {total_pages} pages of memory");
                size = total_pages * Environment.SystemPageSize;

                base_addr = NativeDeclarations.VirtualAlloc(IntPtr.Zero, (uint)(total_pages * Environment.SystemPageSize), NativeDeclarations.MEM_RESERVE, NativeDeclarations.PAGE_EXECUTE_READWRITE);
                Logger.Debug($"Mapped image base @ 0x{base_addr.ToInt64():x}");
                int num_pages = 0;

                for (int i =0; i<this.section_headers.Count; i++ )
                {
                    var section_header = section_headers[i];
                    Logger.Debug($"Section {Encoding.ASCII.GetString(section_header.Name)} @ {section_header.PointerToRawData:X} sized {section_header.SizeOfRawData:X}");
                    if (section_header.SizeOfRawData != 0)
                    {
                        // how many pages will this section take up?
                        int section_pages = (int)section_header.SizeOfRawData / Environment.SystemPageSize;
                        // round up
                        if (section_header.SizeOfRawData % Environment.SystemPageSize != 0)
                        {
                            section_pages++;
                        }
                        Logger.Debug($"This section needs {section_pages} pages");
                        // we allocate section_pages * pagesize bytes
                        var addr = NativeDeclarations.VirtualAlloc(IntPtr.Add(this.base_addr, num_pages * Environment.SystemPageSize), (uint)(section_pages * Environment.SystemPageSize), NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
                        num_pages+=section_pages;
                        Logger.Debug($"Copying section to 0x{addr.ToInt64():X}");
                        // but we only copy sizeofrawdata (which will almost always be less than the amount we allocated)
                        Marshal.Copy(file_contents, (int)section_header.PointerToRawData, addr, (int)section_header.SizeOfRawData);
                        Logger.Debug($"Updating section ptrToRawData to {(addr.ToInt64() - this.base_addr.ToInt64()):X}");
                        // We can't directly modify the section header in the list as it's a struct. 
                        // TODO - look at using an array rather than a list
                        // for now, replace it with a new struct with the new offset
                        var new_hdr = section_headers[i];
                        new_hdr.PointerToRawData = (uint)(addr.ToInt64() - this.base_addr.ToInt64());
                        section_headers[i] = new_hdr;

                        // because we change the section header entry to have our new address, it's hard to work out later what permissions apply to what memory pages
                        // so we record that in this list for future use (post-relocations and patching)
                        permissions.Add(new Permissions(addr, section_header.Characteristics, num_pages * Environment.SystemPageSize, Encoding.ASCII.GetString(section_header.Name)));

                    }
                }

                

                // Process relocations
                Logger.Debug("Processing relocations...");
                section_headers.ForEach(ResolveRelocs);


                // Compilers use different prefixes to symbols depending on architecture. 
                // There might be other naming conventions for functions imported in different ways, but I'm not sure.
                if (this.BofArch == ARCH.I386)
                {
                    this.ImportPrefix = "__imp__";
                    this.HelperPrefix = "_"; // This I think means a global function
                    this.EntrySymbol = "_go";
                }
                else if (this.BofArch == ARCH.AMD64)
                {
                    this.ImportPrefix = "__imp_";
                    this.EntrySymbol = "go";
                    this.HelperPrefix = String.Empty;
                }
            }
            catch (Exception e)
            {
                Logger.Error($"Unable to load object file - {e}");
                throw (e);
            }

        }

        public void SetPermissions()
        {
            // how do we know if we allocated this section?
            foreach (var perm in this.permissions)
            {


                bool x = (perm.Characteristics & NativeDeclarations.IMAGE_SCN_MEM_EXECUTE) != 0;
                bool r = (perm.Characteristics & NativeDeclarations.IMAGE_SCN_MEM_READ) != 0;
                bool w = (perm.Characteristics & NativeDeclarations.IMAGE_SCN_MEM_WRITE) != 0;
                uint page_permissions = 0;

                if (x & r & w) page_permissions = NativeDeclarations.PAGE_EXECUTE_READWRITE;
                if (x & r & !w) page_permissions = NativeDeclarations.PAGE_EXECUTE_READ;
                if (x & !r & !w) page_permissions = NativeDeclarations.PAGE_EXECUTE;

                if (!x & r & w) page_permissions = NativeDeclarations.PAGE_READWRITE;
                if (!x & r & !w) page_permissions = NativeDeclarations.PAGE_READONLY;
                if (!x & !r & !w) page_permissions = NativeDeclarations.PAGE_NOACCESS;

                if (page_permissions == 0)
                {
                    throw new Exception($"Unable to parse section memory permissions for section {perm.SectionName}: 0x{perm.Characteristics:x}");
                }

                Logger.Debug($"Setting permissions for section {perm.SectionName} @ {perm.Addr.ToInt64():X} to R: {r}, W: {w}, X: {x}");

                NativeDeclarations.VirtualProtect(perm.Addr, (UIntPtr)(perm.Size), page_permissions, out _);
                
            }

        }

        public IntPtr ResolveHelpers(byte[] serialised_args, bool debug)
        {
            Logger.Debug("Looking for beacon helper functions");
            bool global_buffer_found = false;
            bool global_buffer_len_found = false;
            bool argument_buffer_found = false;
            bool argument_buffer_length_found = false;
            IntPtr entry_addr = IntPtr.Zero;

            foreach (var symbol in this.symbols) 
            {
                var symbol_name = GetSymbolName(symbol);
                if ((symbol_name.StartsWith(this.HelperPrefix+"Beacon") || symbol_name.StartsWith(this.HelperPrefix + "toWideChar")) && symbol.Type == IMAGE_SYMBOL_TYPE.IMAGE_SYM_TYPE_FUNC)
                {
                    var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);

                    Logger.Debug($"\tFound helper function {symbol_name} - {symbol.Value}");
                    Logger.Debug($"\t[=] Address: {symbol_addr.ToInt64():X}");
                    this.iat.Add(this.InternalDLLName, symbol_name.Replace("_", string.Empty), symbol_addr);
                }
                else if (symbol_name == this.HelperPrefix+"global_buffer")
                {

                    var heap_handle = NativeDeclarations.GetProcessHeap();
                    var mem = NativeDeclarations.HeapAlloc(heap_handle, (uint)NativeDeclarations.HeapAllocFlags.HEAP_ZERO_MEMORY, (uint)this.global_buffer_size);
                    //this.global_buffer = NativeDeclarations.VirtualAlloc(IntPtr.Zero, (uint)this.global_buffer_size, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
                    Logger.Debug($"Allocated a {this.global_buffer_size} bytes global buffer @ {mem.ToInt64():X}");

                    var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);

                    Logger.Debug("Found global buffer");
                    Logger.Debug($"\t[=] Address: {symbol_addr.ToInt64():X}");
                    //write the address of the global buffer we allocated to allow it to move around (e.g. realloc)
                    Marshal.WriteIntPtr(symbol_addr, mem);
                    this.global_buffer = symbol_addr;
                    // save the location of our global_buffer_ptr

                    global_buffer_found = true;
                }
                else if (symbol_name == this.HelperPrefix + "argument_buffer")
                {
                    if (serialised_args.Length > 0)
                    {
                        Logger.Debug($"Allocating argument buffer of length {serialised_args.Length}");
                        this.argument_buffer = NativeDeclarations.VirtualAlloc(IntPtr.Zero, (uint)serialised_args.Length, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_READWRITE);
                        // Copy our data into it 
                        Marshal.Copy(serialised_args, 0, this.argument_buffer, serialised_args.Length);

                        var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);
                        Marshal.WriteIntPtr(symbol_addr, this.argument_buffer);
                    } // TODO - leave dangling if don't have any arguments? A little dangerous, but our code should check the length first....
                    argument_buffer_found = true;

                }
                else if (symbol_name == this.HelperPrefix + "argument_buffer_length")
                {
                    Logger.Debug($"Setting argument length to {(uint)serialised_args.Length}");
                    this.argument_buffer_size = serialised_args.Length;

                    var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);
                    // CAUTION - the sizeo of what you write here MUST match the definition in beacon_funcs.h for argument_buffer_len (currently a uint32_t)

                    Marshal.WriteInt32(symbol_addr, this.argument_buffer_size);
                    argument_buffer_length_found = true;
                }
                else if (symbol_name == this.HelperPrefix+"global_buffer_len")
                {
                    var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);
                    // write the maximum size of the buffer TODO - this shouldn't be hardcoded
                    //Logger.Debug("Found maxlen");
                    //Logger.Debug($"\t[=] Address: {symbol_addr.ToInt64():X}");
                    // CAUTION - the sizeo of what you write here MUST match the definition in beacon_funcs.h for global_buffer_maxlen (currently a uint32_t)
                    Marshal.WriteInt32(symbol_addr, this.global_buffer_size);
                    this.global_buffer_size_ptr = symbol_addr;
                    global_buffer_len_found = true;

                }
                else if (symbol_name == this.HelperPrefix+this.EntryWrapperSymbol)
                {
                    entry_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);
                    Logger.Debug($"Resolved entry address ({this.HelperPrefix + this.EntryWrapperSymbol}) to {entry_addr.ToInt64():X}");
                }
                else if (symbol_name == this.HelperPrefix + "global_debug_flag") {
                    var symbol_addr = new IntPtr(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbol.SectionNumber - 1].PointerToRawData);


                    if (debug)
                    {
                        Marshal.WriteInt32(symbol_addr, 1);
                    } else
                    {
                        Marshal.WriteInt32(symbol_addr, 0);
                    }
                }

            }
            if (!global_buffer_found || !global_buffer_len_found || !argument_buffer_found || !argument_buffer_length_found) throw new Exception($"Unable to find a required symbol in your helper object: global_buffer: {global_buffer_found} \nglobal_buffer_len: {global_buffer_len_found} \nargument_buffer: {argument_buffer_found} \nargument_buffer_length: {argument_buffer_length_found}");
            if (entry_addr == IntPtr.Zero) throw new Exception($"Unable to find entry point {this.HelperPrefix+this.EntryWrapperSymbol}");
            return entry_addr;
        }

        public void StitchEntry(string Entry)
        {
            IntPtr entry = new IntPtr();
            Logger.Debug($"Finding our entry point ({Entry}() function)");

            foreach (var symbol in symbols)
            {

                // find the __go symbol address that represents our entry point
                if (GetSymbolName(symbol).Equals(this.HelperPrefix + Entry))
                {
                    Logger.Debug($"\tFound our entry symbol {this.HelperPrefix + Entry}");
                    // calculate the address
                    // the formula is our base_address + symbol value + section_offset
                    int i = this.symbols.IndexOf(symbol);
                    entry = (IntPtr)(this.base_addr.ToInt64() + symbol.Value + this.section_headers[(int)symbols[i].SectionNumber - 1].PointerToRawData); // TODO not sure about this cast 
                    Logger.Debug($"\tFound address {entry.ToInt64():x}");

                    // now need to update our IAT with this address
                    this.iat.Update(this.InternalDLLName, Entry, entry);

                    break;
                }

            }

            if (entry == IntPtr.Zero)
            {
                Logger.Error($"Unable to find entry point! Does your bof have a {Entry}() function?");
                throw new Exception("Unable to find entry point");
            }

           
        }

        internal void Clear()
        {

            // Note the global_buffer must be cleared *before* the COFF as we need to read its location from the COFF's memory
            if (this.global_buffer != IntPtr.Zero)
            {

                Logger.Debug($"Zeroing and freeing loaded global buffer at 0x{this.global_buffer.ToInt64():X} with size 0x{this.global_buffer_size:X}");
                
                // the global_buffer can move around if the BOF reallocs to make it bigger so we need to read its final location from memory
                var output_addr = Marshal.ReadIntPtr(this.global_buffer);
                var output_size = Marshal.ReadInt32(this.global_buffer_size_ptr);

                NativeDeclarations.ZeroMemory(output_addr, output_size);
                var heap_handle = NativeDeclarations.GetProcessHeap();

                NativeDeclarations.HeapFree(heap_handle, 0, output_addr);
            }

            if (this.argument_buffer != IntPtr.Zero)
            {
                Logger.Debug($"Zeroing and freeing arg buffer at 0x{this.argument_buffer.ToInt64():X} with size 0x{this.argument_buffer_size:X}");

                NativeDeclarations.ZeroMemory(this.argument_buffer, this.argument_buffer_size);
                NativeDeclarations.VirtualFree(this.argument_buffer, 0, NativeDeclarations.MEM_RELEASE);
            }

            Logger.Debug($"Zeroing and freeing loaded COFF image at 0x{this.base_addr:X} with size 0x{this.size:X}");

            // Make sure mem is writeable
            foreach (var perm in this.permissions)
            {
                NativeDeclarations.VirtualProtect(perm.Addr, (UIntPtr)(perm.Size), NativeDeclarations.PAGE_READWRITE, out _);

            }
            // zero out memory
            NativeDeclarations.ZeroMemory(this.base_addr, (int)this.size);
            NativeDeclarations.VirtualFree(this.base_addr, 0, NativeDeclarations.MEM_RELEASE);


        }
        

        private bool ArchitectureCheck()
        {
            this.BofArch = this.file_header.Machine == IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_AMD64 ? ARCH.AMD64 : ARCH.I386;

            if (this.BofArch == this.MyArch) return true;
            return false;

        }

        private void FindSections()
        {
            this.stream.Seek(Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)), SeekOrigin.Begin); // the first section header is located directly after the IMAGE_FILE_HEADER
            for (int i=0; i < this.file_header.NumberOfSections; i++)
            {
                this.section_headers.Add(Deserialize<IMAGE_SECTION_HEADER>(reader.ReadBytes(Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)))));
            }

            // TODO - initialise BSS section as zero. For now, not a problem as Cobalt doesn't do this so you're told to init anything to use;
        }

        private void FindSymbols()
        {
            this.stream.Seek(this.file_header.PointerToSymbolTable, SeekOrigin.Begin);

            for (int i = 0; i < this.file_header.NumberOfSymbols; i++)
            {
                this.symbols.Add(Deserialize<IMAGE_SYMBOL>(reader.ReadBytes(Marshal.SizeOf(typeof(IMAGE_SYMBOL)))));
            }
            Logger.Debug($"Created list of {this.symbols.Count} symbols");

        }


        private void ResolveRelocs(IMAGE_SECTION_HEADER section_header)
        {
            if (section_header.NumberOfRelocations > 0)
            {
                Logger.Debug($"Processing {section_header.NumberOfRelocations} relocations for {Encoding.ASCII.GetString(section_header.Name)} section from offset {section_header.PointerToRelocations:X}");
                this.stream.Seek(section_header.PointerToRelocations, SeekOrigin.Begin);

                for (int i = 0; i < section_header.NumberOfRelocations; i++)
                {
                    var struct_bytes = reader.ReadBytes(Marshal.SizeOf(typeof(IMAGE_RELOCATION)));

                    IMAGE_RELOCATION reloc = Deserialize<IMAGE_RELOCATION>(struct_bytes);
                    Logger.Debug($"Got reloc info: {reloc.VirtualAddress:X} - {reloc.SymbolTableIndex:X} - {reloc.Type} - @ { (this.base_addr + (int)section_header.PointerToRawData + (int)reloc.VirtualAddress).ToInt64():X}");

                    if ((int)reloc.SymbolTableIndex > this.symbols.Count || (int)reloc.SymbolTableIndex < 0)
                    {
                        throw new Exception($"Unable to parse relocation # {i+1} symbol table index - {reloc.SymbolTableIndex}");
                    }
                    IMAGE_SYMBOL reloc_symbol = this.symbols[(int)reloc.SymbolTableIndex];
                    var symbol_name = GetSymbolName(reloc_symbol);
                    Logger.Debug($"Relocation name: {symbol_name}");
                    if (reloc_symbol.SectionNumber == IMAGE_SECTION_NUMBER.IMAGE_SYM_UNDEFINED)
                    {

                        IntPtr func_addr;

                        if (symbol_name.StartsWith(this.ImportPrefix + "Beacon") || symbol_name.StartsWith(this.ImportPrefix + "toWideChar"))
                        {

                            Logger.Debug("We need to provide this function");
                            // we need to write the address of the IAT entry for the function to this location

                            var func_name = symbol_name.Replace(this.ImportPrefix, String.Empty);
                            func_addr = this.iat.Resolve(this.InternalDLLName, func_name);

                        }
                        else if (symbol_name == this.ImportPrefix + this.EntrySymbol)
                        {
                            // this entry is found in out beacon_funcs object, and needs filling in with a ptr to the address of the go function in our actual BOF.
                            // We don't know this yet (until that is loaded), so we add an entry to the IAT we'll fill in later.

                            // in this case, it seems to want the address itself??
                            func_addr = this.iat.Add(this.InternalDLLName, this.EntrySymbol, IntPtr.Zero);


                        }
                        else
                        {
                            // This is a win32 api function

                            Logger.Debug("Win32API function");

                            string symbol_cleaned = symbol_name.Replace(this.ImportPrefix, "");
                            string dll_name;
                            string func_name;
                            if (symbol_cleaned.Contains("$"))
                            {

                                string[] symbol_parts = symbol_name.Replace(this.ImportPrefix, "").Split('$');


                                try
                                {
                                    dll_name = symbol_parts[0];
                                    func_name = symbol_parts[1].Split('@')[0]; // some compilers emit the number of bytes in the param list after the fn name
                                }
                                catch (Exception e)
                                {

                                    throw new Exception($"Unable to parse function name {symbol_name} as DLL$FUNCTION while processing relocations - {e}");
                                }
                            }
                            else
                            {
                                // TODO - some of the CS SA BOFs have no prefix?? Is this what CobalStrike does?kh
                                dll_name = "KERNEL32";
                                func_name = symbol_cleaned.Split('@')[0];

                            }

                            func_addr = this.iat.Resolve(dll_name, func_name);

                        }

                        // write our address to the relocation
                        IntPtr reloc_location = this.base_addr + (int)section_header.PointerToRawData + (int)reloc.VirtualAddress;
                        Int64 current_value = Marshal.ReadInt32(reloc_location);
                        Logger.Debug($"Current value: {current_value:X}");

                        // How we write our relocation depends on the relocation type and architecture
                        // Note - "in the wild" most of these are not used, which makes it a bit difficult to test. 
                        // For example, in all the BOF files I've seen only four are actually used. 
                        // An exception will be thrown if not supported
                        // TODO - we should refactor this, but my head is hurting right now. 
                        // TODO - need to check when in 64 bit mode that any 32 bit relocation's don't overflow (will .net do this for free?)

                        switch (reloc.Type)
                        {
#if _I386
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_ABSOLUTE:
                                // The relocation is ignored
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR16:
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_REL16:
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SEG12:
                                // The relocation is not supported;
                                break;

                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR32:
                                // The target's 32-bit VA.

                                Marshal.WriteInt32(reloc_location, func_addr.ToInt32());
                                break;



                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_REL32:
                                // TODO - not seen this "in the wild"
                                Marshal.WriteInt32(reloc_location, (func_addr.ToInt32()-4) - reloc_location.ToInt32());
                                break;

                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR32NB:
                                // The target's 32-bit RVA.
                                Marshal.WriteInt32(reloc_location, (func_addr.ToInt32() - 4) - reloc_location.ToInt32() - this.base_addr.ToInt32());
                                break;

                            // These relocations will fall through as unhandled for now
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECTION:
                            // The 16-bit section index of the section that contains the target. This is used to support debugging information.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECREL:
                            // The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_TOKEN:
                            // The CLR token.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECREL7:
                            // A 7-bit offset from the base of the section that contains the target.


#elif _AMD64
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32:
                                Marshal.WriteInt32(reloc_location, (int)((func_addr.ToInt64()-4) - (reloc_location.ToInt64()))); // subtract the size of the relocation (relative to the end of the reloc)
                                break;

#endif
                            default:
                                throw new Exception($"Unable to process function relocation type {reloc.Type} - please file a bug report.");
                    }
                        Logger.Debug($"\tWrite relocation to {reloc_location.ToInt64():X}");


                    }
                    else
                    {
                        Logger.Debug("\tResolving internal reference");
                        IntPtr reloc_location = this.base_addr + (int)section_header.PointerToRawData + (int)reloc.VirtualAddress;
                        Logger.Debug($"reloc_location: 0x{reloc_location.ToInt64():X}, section offset: 0x{section_header.PointerToRawData:X} reloc VA: {reloc.VirtualAddress:X}");
#if _I386
                        Int32 current_value = Marshal.ReadInt32(reloc_location);
                        Int32 object_addr;
#elif _AMD64
                        Int64 current_value = Marshal.ReadInt64(reloc_location);
                        Int32 current_value_32 = Marshal.ReadInt32(reloc_location);
                        Int64 object_addr;
#endif
                        switch (reloc.Type)
                        {
#if _I386
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_ABSOLUTE:
                                // The relocation is ignored
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR16:
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_REL16:
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SEG12:
                                // The relocation is not supported;
                                break;

                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR32:
                                // The target's 32-bit VA
                                Marshal.WriteInt32(reloc_location, current_value + this.base_addr.ToInt32() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData);
                                break;

                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_REL32:
                                // The target's 32-bit RVA
                                object_addr = current_value + this.base_addr.ToInt32() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (object_addr-4) - reloc_location.ToInt32() );
                                break;


                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_DIR32NB:
                                // The target's 32-bit RVA.
                                object_addr = current_value + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (object_addr - 4) - reloc_location.ToInt32());
                                break;

                            // These relocations will fall through as unhandled for now
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECTION:
                            // The 16-bit section index of the section that contains the target. This is used to support debugging information.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECREL:
                            // The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_TOKEN:
                            // The CLR token.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_I386_SECREL7:
                            // A 7-bit offset from the base of the section that contains the target.
#elif _AMD64
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_ABSOLUTE:
                                // The relocation is ignored
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_ADDR64:
                                // The 64-bit VA of the relocation target.
                                Marshal.WriteInt64(reloc_location, current_value + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData);
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_ADDR32:
                                // The 32-bit VA of the relocation target.
                                // TODO how does this not overflow?
                                object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (int)(object_addr));
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_ADDR32NB:
                                // The 32-bit address without an image base (RVA).
                                object_addr = current_value_32 + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (int)(object_addr - reloc_location.ToInt64()));
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32:
                                // The 32-bit relative address from the byte following the relocation.
                                object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (int)((object_addr - 4) - (reloc_location.ToInt64()))); // subtract the size of the relocation
                                break;
                                //_1 through _5 written from the spec, not seen in the wild to test
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32_1:
                                // The 32-bit address relative to byte distance 1 from the relocation.
                                object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (int)((object_addr - 3) - (reloc_location.ToInt64()))); // subtract the size of the relocation
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32_2:
                                // The 32-bit address relative to byte distance 2 from the relocation.
                                object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (int)((object_addr - 2) - (reloc_location.ToInt64()))); // subtract the size of the relocation
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32_3:
                                // The 32-bit address relative to byte distance 3 from the relocation.
                                object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (int)((object_addr - 1) - (reloc_location.ToInt64()))); // subtract the size of the relocation
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32_4:
                                // The 32-bit address relative to byte distance 4 from the relocation.
                                object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (int)((object_addr) - (reloc_location.ToInt64()))); // subtract the size of the relocation
                                break;
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_REL32_5:
                                // The 32-bit address relative to byte distance 5 from the relocation.
                                object_addr = current_value_32 + this.base_addr.ToInt64() + (int)this.section_headers[(int)reloc_symbol.SectionNumber - 1].PointerToRawData;
                                Marshal.WriteInt32(reloc_location, (int)((object_addr + 1) - (reloc_location.ToInt64()))); // subtract the size of the relocation
                                break;
                            // These feel like they're unlikely to be used. I've never seen them, and some of them don't make a lot of sense in the context of what we're doing.
                            // Ghidra/IDA don't implement all of these either
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_SECTION:
                                // The 16-bit section index of the section that contains the target. This is used to support debugging information.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_SECREL:
                                // The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_SECREL7:
                                // A 7-bit unsigned offset from the base of the section that contains the target.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_TOKEN:
                                // CLR tokens.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_SREL32:
                                // A 32-bit signed span-dependent value emitted into the object.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_PAIR:
                                // A pair that must immediately follow every span-dependent value.
                            case IMAGE_RELOCATION_TYPE.IMAGE_REL_AMD64_SSPAN32:
                                // A 32-bit signed span-dependent value that is applied at link time.
#endif

                            default:
                                throw new Exception($"Unhandled relocation type {reloc.Type} - please file a bug report");

                        }
                    }   

                }

            }
        }
             
        private string GetSymbolName(IMAGE_SYMBOL symbol)
        {
            if (symbol.Name[0] == 0 && symbol.Name[1] == 0 && symbol.Name[2] == 0 && symbol.Name[3] == 0) 
            {
                // the last four bytes of the Name field contain an offset into the string table.
                uint offset = BitConverter.ToUInt32(symbol.Name, 4);
                long position = this.stream.Position;
                this.stream.Seek(this.string_table + offset, SeekOrigin.Begin);

                // read a C string 
                List<byte> characters = new List<byte>();
                byte c;
                while ((c = reader.ReadByte()) != '\0')
                {
                    characters.Add(c);
                }

                String output = Encoding.ASCII.GetString(characters.ToArray());
                this.stream.Seek(position, SeekOrigin.Begin);
                return output;

            } else
            {
                return Encoding.ASCII.GetString(symbol.Name).Replace("\0", String.Empty);
            } 

        }

        private static T Deserialize<T> (byte[] array) 
            where T:struct
        {
            GCHandle handle = GCHandle.Alloc(array, GCHandleType.Pinned);
            return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        }


    }

    class Permissions
    {
        internal IntPtr Addr;
        internal uint Characteristics;
        internal int Size;
        internal String SectionName;

        public Permissions(IntPtr addr, uint characteristics, int size, String section_name)
        {
            this.Addr = addr;
            this.Characteristics = characteristics;
            this.Size = size;
            this.SectionName = section_name;
        }
    }
}
