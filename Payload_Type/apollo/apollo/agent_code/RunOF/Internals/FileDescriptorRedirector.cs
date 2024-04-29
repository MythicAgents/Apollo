using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RunOF.Internals
{
    class FileDescriptorPair
    {
        public IntPtr Read { get; set; }

        public IntPtr Write { get; set; }
    }

    class FileDescriptorRedirector
    {
        private const int STD_INPUT_HANDLE = -10;
        private const int STD_OUTPUT_HANDLE = -11;
        private const int STD_ERROR_HANDLE = -12;
        private const uint BYTES_TO_READ = 1024;


        private IntPtr oldGetStdHandleOUT;
        private IntPtr oldGetStdHandleIN;
        private IntPtr oldGetStdHandleERROR;

        private FileDescriptorPair kpStdOutPipes;
        private FileDescriptorPair kpStdInPipes;
        private Task<string> readTask;

        public bool RedirectFileDescriptors()
        {
            oldGetStdHandleOUT = GetStdHandleOUT();
            oldGetStdHandleIN = GetStdHandleIN();
            oldGetStdHandleERROR = GetStdHandleERROR();

#if DEBUG
            Console.WriteLine("[*] Creating STDOut Pipes to redirect to");
#endif
            kpStdOutPipes = CreateFileDescriptorPipes();
            if (kpStdOutPipes == null)
            {
                return false;
            }

#if DEBUG
            Console.WriteLine("[*] Creating STDIn Pipes to redirect to");
#endif
            kpStdInPipes = CreateFileDescriptorPipes();
            if (kpStdInPipes == null)
            {
                return false;
            }

            return RedirectDescriptorsToPipes(kpStdOutPipes.Write, kpStdInPipes.Write, kpStdOutPipes.Write);
        }

        public string ReadDescriptorOutput()
        {
#if DEBUG
            Console.WriteLine("[*] Retrieving the 'subprocess' stdout & stderr");
#endif
            while (!readTask.IsCompleted)
            {
#if DEBUG
                Console.WriteLine("[*] Waiting for the task reading from pipe to finish...");
#endif
                Thread.Sleep(2000);
            }
            return readTask.Result;
        }

        public void ResetFileDescriptors()
        {
#if DEBUG
            Console.WriteLine("[*] Reset StdError, StdOut, StdIn");
#endif
            RedirectDescriptorsToPipes(oldGetStdHandleOUT, oldGetStdHandleIN, oldGetStdHandleERROR);

            ClosePipes();

        }

        private static IntPtr GetStdHandleOUT()
        {
            return NativeDeclarations.GetStdHandle(STD_OUTPUT_HANDLE);
        }
        private static IntPtr GetStdHandleERROR()
        {
            return NativeDeclarations.GetStdHandle(STD_ERROR_HANDLE);
        }

        internal void ClosePipes()
        {
#if DEBUG
            Console.WriteLine("[*] Closing StdOut pipes");
#endif
            CloseDescriptors(kpStdOutPipes);
#if DEBUG
            Console.WriteLine("[*] Closing StdIn pipes");
#endif
            CloseDescriptors(kpStdInPipes);
        }

        internal void StartReadFromPipe()
        {
            this.readTask = Task.Factory.StartNew(() =>
            {
                string output = "";

                byte[] buffer = new byte[BYTES_TO_READ];
                byte[] outBuffer;

                var ok = NativeDeclarations.ReadFile(kpStdOutPipes.Read, buffer, BYTES_TO_READ, out uint bytesRead, IntPtr.Zero);

                if (!ok)
                {
                    Console.WriteLine($"[-] Unable to read from 'subprocess' pipe");
                    return "";
                }
#if DEBUG
                Console.WriteLine($"[*] Read {bytesRead} bytes from 'subprocess' pipe");
#endif
                if (bytesRead != 0)
                {
                    outBuffer = new byte[bytesRead];
                    Array.Copy(buffer, outBuffer, bytesRead);
                    output += Encoding.Default.GetString(outBuffer);
                }

                while (ok)
                {
                    ok = NativeDeclarations.ReadFile(kpStdOutPipes.Read, buffer, BYTES_TO_READ, out bytesRead, IntPtr.Zero);
#if DEBUG
                    Console.WriteLine($"[*] Read {bytesRead} bytes from 'subprocess' pipe");
#endif
                    if (bytesRead != 0)
                    {
                        outBuffer = new byte[bytesRead];
                        Array.Copy(buffer, outBuffer, bytesRead);
                        output += Encoding.Default.GetString(outBuffer);
                    }
                }
                return output;
            });
        }

        private static IntPtr GetStdHandleIN()
        {
            return NativeDeclarations.GetStdHandle(STD_INPUT_HANDLE);
        }

        private static void CloseDescriptors(FileDescriptorPair stdoutDescriptors)
        {
            // Need to close write before read else it hangs as could still be writing
            if (stdoutDescriptors.Write != IntPtr.Zero)
            {
                NativeDeclarations.CloseHandle(stdoutDescriptors.Write);
#if DEBUG
                Console.WriteLine("[+] CloseHandle write");
#endif
            }

            if (stdoutDescriptors.Read != IntPtr.Zero)
            {
                NativeDeclarations.CloseHandle(stdoutDescriptors.Read);
#if DEBUG
                Console.WriteLine("[+] CloseHandle read");
#endif
            }
        }

        private static FileDescriptorPair CreateFileDescriptorPipes()
        {
            NativeDeclarations.SECURITY_ATTRIBUTES lpSecurityAttributes = new NativeDeclarations.SECURITY_ATTRIBUTES();
            lpSecurityAttributes.nLength = Marshal.SizeOf(lpSecurityAttributes);
            lpSecurityAttributes.bInheritHandle = 1;

            var outputStdOut = NativeDeclarations.CreatePipe(out IntPtr read, out IntPtr write, ref lpSecurityAttributes, 0);
            if (!outputStdOut)
            {
#if DEBUG

                Console.WriteLine("[-] Cannot create File Descriptor pipes");
#endif
                return null;
            }
#if DEBUG
            else
            {
                Console.WriteLine("[+] Created File Descriptor pipes: ");
                Console.WriteLine($"\t[*] Read: 0x{read.ToString("X")}");
                Console.WriteLine($"\t[*] Write: 0x{write.ToString("X")}");
            }
#endif
            return new FileDescriptorPair
            {
                Read = read,
                Write = write
            };
        }

        private static bool RedirectDescriptorsToPipes(IntPtr hStdOutPipes, IntPtr hStdInPipes, IntPtr hStdErrPipes)
        {
            bool bStdOut = NativeDeclarations.SetStdHandle(STD_OUTPUT_HANDLE, hStdOutPipes);
            if (bStdOut)
            {
#if DEBUG
                Console.WriteLine($"[+] SetStdHandle STDOUT to 0x{hStdOutPipes.ToInt64():X} ");
            }
            else
            {
                Console.WriteLine($"[-] Unable to SetStdHandle STDOUT to 0x{hStdOutPipes.ToInt64():X} ");
                return false;
#endif
            }

            bool bStdError = NativeDeclarations.SetStdHandle(STD_ERROR_HANDLE, hStdErrPipes);
            if (bStdError)
            {
#if DEBUG
                Console.WriteLine($"[+] SetStdHandle STDERROR to 0x{hStdErrPipes.ToInt64():X}");
            }
            else
            {
                Console.WriteLine($"[-] Unable to SetStdHandle STDERROR  to 0x{hStdErrPipes.ToInt64():X} ");
                return false;
#endif
            }

            bool bStdIn = NativeDeclarations.SetStdHandle(STD_INPUT_HANDLE, hStdInPipes);
            if (bStdIn)
            {
#if DEBUG
                Console.WriteLine($"[+] SetStdHandle STDIN to 0x{hStdInPipes.ToInt64():X} ");
            }
            else
            {
                Console.WriteLine($"[-] Unable to SetStdHandle STDIN to 0x{hStdInPipes.ToInt64():X} ");
                return false;
#endif
            }
            return true;
        }

    }
}