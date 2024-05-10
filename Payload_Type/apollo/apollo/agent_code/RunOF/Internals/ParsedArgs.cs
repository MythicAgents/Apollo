using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace RunOF.Internals
{

    public class ParsedArgs
    {
        internal string filename;
        internal byte[] file_bytes;
        internal int thread_timeout = 30000;
        internal string entry_name = "go";
        private const int ERROR_INVALID_COMMAND_LINE = 0x667;
        internal List<OfArg> of_args;
        public bool debug = false;

        public ParsedArgs(string[] args)
        {

            // Set our log level
            if (args.Contains("-v"))
            {
                Logger.Level = Logger.LogLevels.DEBUG;
                this.debug = true;
            }

            if (args.Contains("-h"))
            {
                throw new ArgumentNullException();
            }

            Logger.Debug($"Parsing {args.Length} Arguments: {string.Join(" ", args)}");
            of_args = new List<OfArg>();
            // Mandatory arguments are either file (-f) or base 64 encoded bytes(-b)
            if (!args.Contains("-f") && !args.Contains("-a"))
            {
                throw new ArgumentException("Invalid Command Line");
            }

            if (args.Contains("-f"))
            {
                try
                {
                    filename = ExtractArg(args, "-f");
                    try
                    {
                        file_bytes = File.ReadAllBytes(filename);
                    } catch (Exception e)
                    {
                        Logger.Error($"Unable to read file {filename} : {e}");
                        throw new ArgumentException($"Unable to open provided filename: {e} ");
                    }

                }
                catch
                {
                    throw new ArgumentException("Unable to extract filename from arguments (use -f <filename>");
                }
            } 
            else if (args.Contains("-a"))
            {
                try
                {
                    file_bytes = Convert.FromBase64String(ExtractArg(args, "-a"));
                } catch (Exception e)
                {
                    throw new ArgumentException($"Unable to extract binary object file from arguments (use -a <b64_blog> \n {e}");
                }
            }


            // Set our thread timeout (seconds).
            // This can be a number, or -1
            if (args.Contains("-t"))
            {
                try
                {
                    int t = int.Parse(ExtractArg(args, "-t"));
                    if (t>=0)
                    {
                        this.thread_timeout = t * 1000;
                    } else if (t==-1)
                    {
                        this.thread_timeout = -1;
                    } else
                    {
                        Logger.Error("Timeout cannot be less than -1, ignoring");
                    }

                } catch (Exception e)
                {
                    throw new ArgumentException("Unable to handle timeout argument \n {e}");
                }
            }

            if (args.Contains("-e"))
            {
                try
                {
                    this.entry_name = ExtractArg(args, "-e");

                } catch(Exception e)
                { 
                    throw new ArgumentException($"Unable to handle entry point argument \n {e}");
                }
            }

            // Now read in any optional arguments that get provided to the OF. 
            foreach (var arg in args)
            {
                if (arg.StartsWith("-b:")) //binary data, base64
                {
                    try
                    {
                        of_args.Add(new OfArg(Convert.FromBase64String(arg.Substring(3))));

                    } catch (Exception e)
                    {
                        Logger.Error($"Unable to parse OF argument -b as a base64 array: {e}");
                    }
                } else if (arg.StartsWith("-i:")) //uint32
                {
                    try
                    {
                        of_args.Add(new OfArg(UInt32.Parse(arg.Substring(3))));
                    }
                    catch (Exception e)
                    {
                        Logger.Error($"Unable to parse OF argument -i as a uint32: {e}");
                    }

                } else if (arg.StartsWith("-s:")) //uint16
                {
                    try
                    {
                        of_args.Add(new OfArg(UInt16.Parse(arg.Substring(3))));
                    }
                    catch (Exception e)
                    {
                        Logger.Error($"Unable to parse OF argument -s as a uint16: {e}");
                    }
                }
                else if (arg.StartsWith("-z:")) //ASCII string
                {
                    try
                    {
                        of_args.Add(new OfArg(arg.Substring(3) + "\0")); // ensure is null-terminated
 
                    }
                    catch (Exception e)
                    {
                        Logger.Error($"Unable to parse OF argument -z as a string: {e}");
                    }
                } else if (arg.StartsWith("-Z:")) //UTF-16 string
                {
                    try
                    {
                        of_args.Add(new OfArg(Encoding.Unicode.GetBytes(arg.Substring(3) + "\0\0"))); // ensure is null-terminated
                    }
                    catch (Exception e)
                    {
                        Logger.Error($"Unable to parse OF argument -Z as a string: {e}");
                    }
                }
            }
        }

        public byte[] SerialiseArgs()
        {
            List<byte> output_bytes = new List<byte>();
            Logger.Debug($"Serialising {this.of_args.Count} object file arguments ");
            // convert our list of arguments into a byte array
            foreach (var of_arg in this.of_args)
            {
                Logger.Debug($"\tSerialising arg of type {of_arg.arg_type} [{(UInt32)of_arg.arg_type}:X]");
                // Add the type
                output_bytes.AddRange(BitConverter.GetBytes((UInt32)of_arg.arg_type));
                // Add the length
                output_bytes.AddRange(BitConverter.GetBytes((UInt32)of_arg.arg_data.Count()));
                // Add the data
                output_bytes.AddRange(of_arg.arg_data);
            }
            return output_bytes.ToArray();
            
        }

        private string ExtractArg(string[] args, string key)
        {
            if (!args.Contains(key)) throw new Exception($"Args array does not contains key {key}");
            if (args.Count() > Array.IndexOf(args, key))
            {
                return args[Array.IndexOf(args, key) + 1];
            }
            else
            {
                throw new Exception($"Key {key} does not have a value");
            }

        }
    }

    class OfArg
    {

        public enum ArgType: UInt32
        {
            BINARY,
            INT32,
            INT16,
            STR,
            WCHR_STR,

        }

        public byte[] arg_data;

        public ArgType arg_type;
        public OfArg(UInt32 arg_data)
        {
            arg_type = ArgType.INT32;
            this.arg_data = BitConverter.GetBytes(arg_data);
        }

        public OfArg(UInt16 arg_data)
        {
            arg_type = ArgType.INT16;
            this.arg_data = BitConverter.GetBytes(arg_data);

        }

        public OfArg(string arg_data)
        {
            arg_type = ArgType.BINARY;
            this.arg_data = Encoding.ASCII.GetBytes(arg_data+"\0");
        }



        public OfArg(byte[] arg_data)
        { 
            arg_type = ArgType.BINARY;
            this.arg_data = arg_data;
        }
   
    }

}
