using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;
using System.Text;
using System.IO;
using System.Reflection;

namespace RunOF.Internals
{
    public class BofRunner
    {
        private readonly Coff beacon_helper;
        private Coff bof;
        public IntPtr entry_point;
        private readonly IAT iat;
        public ParsedArgs parsed_args;
        public BofRunner(ParsedArgs parsed_args)
        {
            Logger.Debug("Initialising bof runner");
            this.parsed_args = parsed_args;

            // first we need a basic IAT to hold function pointers
            // this needs to be done here so we can share it between our two object files
            this.iat = new IAT();

            // First init our beacon helper object file 
            // This has the code for things like BeaconPrintf, BeaconOutput etc.
            // It also has a wrapper for the bof entry point (go_wrapper) that allows us to pass arguments. 
            byte[] beacon_funcs;
            string [] resource_names = Assembly.GetExecutingAssembly().GetManifestResourceNames();

            string resource_name = Environment.Is64BitProcess ? "RunOF.beacon_funcs.x64.o" : "RunOF.beacon_funcs.x86.o";

            if (resource_names.Contains(resource_name))
            {
                var ms = new MemoryStream();
                Stream resStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource_name);
                resStream.CopyTo(ms);
                beacon_funcs = ms.ToArray();
            } else
            {
                throw new Exception("Unable to load beacon_funcs resource");
            }

            try
            {
                this.beacon_helper = new Coff(beacon_funcs, this.iat);

            } catch (Exception e)
            {
                throw e;
            }

            // Serialise the arguments we want to send to our object file
            // Find our helper functions and entry wrapper (go_wrapper)
            this.entry_point = this.beacon_helper.ResolveHelpers(parsed_args.SerialiseArgs(), parsed_args.debug);

            // this needs to be called after we've finished monkeying around with the BOF's memory
            this.beacon_helper.SetPermissions();

        }

        public void LoadBof()
        {

            Logger.Debug("Loading boff object...");
            // create new coff
            this.bof = new Coff(this.parsed_args.file_bytes, this.iat);
            Logger.Debug($"Loaded BOF with entry {this.entry_point.ToInt64():X}");
            // stitch up our go_wrapper and go functions
            this.bof.StitchEntry(this.parsed_args.entry_name);

            this.bof.SetPermissions();
        }

        public BofRunnerOutput RunBof()
        {
            Logger.Debug($"Starting bof in new thread @ {this.entry_point.ToInt64():X}");
            Logger.Debug(" --- MANAGED CODE END --- ");
            IntPtr hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, this.entry_point, IntPtr.Zero, 0, IntPtr.Zero);
            var resp = NativeDeclarations.WaitForSingleObject(hThread, (uint)(parsed_args.thread_timeout));

            if (resp == (uint)NativeDeclarations.WaitEventEnum.WAIT_TIMEOUT)
            {
                Logger.Info($"BOF timed out after {parsed_args.thread_timeout / 1000} seconds");
            }

            Console.Out.Flush();
            Logger.Debug(" --- MANAGED CODE START --- ");

            int ExitCode;

            NativeDeclarations.GetExitCodeThread(hThread, out ExitCode);

            
            if (ExitCode < 0)
            {
                Logger.Info($"Bof thread exited with code {ExitCode} - see above for exception information. ");

            }


            // try reading from our shared buffer
            // the buffer may have moved (e.g. if realloc'd) so we need to get its latest address
            var output_addr = Marshal.ReadIntPtr(beacon_helper.global_buffer);
            // NB this is the size of the allocated buffer, not its contents, and we'll read all of its size - this may or may not be an issue depending on what is written
            var output_size = Marshal.ReadInt32(beacon_helper.global_buffer_size_ptr);

            Logger.Debug($"Output buffer size {output_size} located at {output_addr.ToInt64():X}");
            List<byte> output = new List<byte>();

            byte c;
            int i = 0;
            while ((c = Marshal.ReadByte(output_addr + i)) != '\0' && i < output_size) {
                output.Add(c);
                i++;
            }

            // Now cleanup all memory...
            BofRunnerOutput Response = new BofRunnerOutput();
            Response.Output = Encoding.ASCII.GetString(output.ToArray());
            Response.ExitCode = ExitCode;
            ClearMemory();

            return Response;
            
        }

        private void ClearMemory()
        {
            /* things that need cleaning up:
                - beacon_funcs BOF
                - the bof we ran
                - all of our input/output buffers
                - our IAT table
            */
            // this.beacon_helper.base_addr, t
            this.beacon_helper.Clear();
            this.bof.Clear();
            this.iat.Clear();

        }
    }

    public class BofRunnerOutput
    {
        public string Output;
        public int ExitCode;
    }
}
