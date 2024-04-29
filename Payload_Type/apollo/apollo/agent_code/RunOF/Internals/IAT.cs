using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace RunOF.Internals
{
    class IAT
    {
        private readonly IntPtr iat_addr;
        private int iat_pages;
        private int iat_count;
        private readonly Dictionary<String, IntPtr> iat_entries;
        public IAT()
        {
            this.iat_pages = 2;
            this.iat_addr = NativeDeclarations.VirtualAlloc(IntPtr.Zero, (uint)(this.iat_pages * Environment.SystemPageSize), NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
            this.iat_count = 0;
            this.iat_entries = new Dictionary<string, IntPtr>();
        }
        public IntPtr Resolve(string dll_name, string func_name)
        {
            // do we already have it in our IAT table? It not lookup and add
            if (!this.iat_entries.ContainsKey(dll_name + "$" + func_name))
            {
                Logger.Debug($"Resolving {func_name} from {dll_name}");

                IntPtr dll_handle = NativeDeclarations.LoadLibrary(dll_name);
                IntPtr func_ptr = NativeDeclarations.GetProcAddress(dll_handle, func_name);
                if (func_ptr == null || func_ptr.ToInt64() == 0)
                {
                    throw new Exception($"Unable to resolve {func_name} from {dll_name}");
                }
                Logger.Debug($"\tGot function address {func_ptr.ToInt64():X}");
                Add(dll_name, func_name, func_ptr);
            }

            return this.iat_entries[dll_name + "$" + func_name];

        }

        // This can also be called directly for functions where you already know the address (e.g. helper functions)
        public IntPtr Add(string dll_name, string func_name, IntPtr func_address)
        {
#if _I386
            Logger.Debug($"Adding {dll_name+ "$" + func_name} at address {func_address.ToInt64():X} to IAT address {this.iat_addr.ToInt64() + (this.iat_count * 4):X}");

            if (this.iat_count * 4 > (this.iat_pages * Environment.SystemPageSize))
            {
                throw new Exception("Run out of space for IAT entries!");
            }
            Marshal.WriteInt32(this.iat_addr + (this.iat_count * 4), func_address.ToInt32());
            this.iat_entries.Add(dll_name + "$" + func_name, this.iat_addr + (this.iat_count * 4));
            this.iat_count++;

            return this.iat_entries[dll_name + "$" + func_name]; 


#elif _AMD64
            Logger.Debug($"Adding {dll_name + "$" + func_name} at address {func_address.ToInt64():X} to IAT address {this.iat_addr.ToInt64() + (this.iat_count * 8):X}");


            // check we have space in our IAT table
            if (this.iat_count * 8 > (this.iat_pages * Environment.SystemPageSize))
            {
                throw new Exception("Run out of space for IAT entries!");
            }

            Marshal.WriteInt64(this.iat_addr + (this.iat_count * 8), func_address.ToInt64());
            this.iat_entries.Add(dll_name + "$" + func_name, this.iat_addr + (this.iat_count * 8));
            this.iat_count++;
            return this.iat_entries[dll_name + "$" + func_name];
#else

            throw new Exception("Unsupported architecture.");

#endif


        }

        public void Update(string dll_name, string func_name, IntPtr func_address)
        {
            if (!this.iat_entries.ContainsKey(dll_name + "$" + func_name)) throw new Exception($"Unable to update IAT entry for {dll_name + "$" + func_name} as don't have an existing entry for it");
            // Write the new address into our IAT memory. 
            // we don't need to update our internal iat_entries dict as that is just a mapping of name to IAT memory location.
#if _I386
            Logger.Debug($"Updating symbol {dll_name + "$" + func_name} @ {this.iat_entries[dll_name + "$" + func_name].ToInt64():X} from {Marshal.ReadInt32(this.iat_entries[dll_name + "$" + func_name]):X} to {func_address.ToInt32():X}");

            Marshal.WriteInt32(this.iat_entries[dll_name + "$" + func_name], func_address.ToInt32());
#elif _AMD64
            Logger.Debug($"Updating symbol {dll_name + "$" + func_name} from {Marshal.ReadInt64(this.iat_entries[dll_name + "$" + func_name]):X} to {func_address.ToInt64():X}");

            Marshal.WriteInt64(this.iat_entries[dll_name + "$" + func_name], func_address.ToInt64());
#endif
        }

        internal void Clear()
        {
            Logger.Debug($"Zeroing and freeing IAT at 0x{this.iat_addr.ToInt64():X} size {this.iat_pages * Environment.SystemPageSize}");
            // zero out memory
            NativeDeclarations.ZeroMemory(this.iat_addr, this.iat_pages * Environment.SystemPageSize);

            // free it
            NativeDeclarations.VirtualFree(this.iat_addr, 0, NativeDeclarations.MEM_RELEASE);


        }
    }
}
