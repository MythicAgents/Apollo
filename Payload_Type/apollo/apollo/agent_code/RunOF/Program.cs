using RunOF.Internals;
using System;
using System.Runtime.CompilerServices;
using System.Diagnostics;

namespace RunOF
{
    class Program
    {
        private const int ERROR_INVALID_COMMAND_LINE = 0x667;

        static int Main(string[] args)
        {

#if _X86
            Logger.Info("Starting RunOF [x86]");
#elif _AMD64
            Logger.Info("Starting RunOF [x64]");

#endif

#if DEBUG
            Logger.Level = Logger.LogLevels.DEBUG;
#endif

            ParsedArgs ParsedArgs;
            try
            {
                ParsedArgs = new ParsedArgs(args);

            } catch (ArgumentNullException)
            {
                return 0;
            } catch (Exception e)
            {
                Logger.Error($"Unable to parse application arguments: \n {e}");
                return -1;
            };


            Logger.Info($"Loading object file {ParsedArgs.filename}");

            try
            {
                BofRunner bof_runner = new BofRunner(ParsedArgs);
                //  bof_runner.LoadBof(filename);

                bof_runner.LoadBof();

                Logger.Info($"About to start BOF in new thread at {bof_runner.entry_point.ToInt64():X}");
                // We only want the press enter to start if a debug build and -v flag supplied, as we might want logs from a non-interactive session
#if DEBUG
                if (ParsedArgs.debug)
                {
                
                    Logger.Debug("Press enter to start it (✂️ attach debugger here...)");
                    Console.ReadLine();
            }
#endif


                var Result = bof_runner.RunBof(30);

                Console.WriteLine("------- BOF OUTPUT ------");
                Console.WriteLine($"{Result.Output}");
                Console.WriteLine("------- BOF OUTPUT FINISHED ------");
#if DEBUG
                if (ParsedArgs.debug)
                {
                    Logger.Debug("Press enter to continue...");
                    Console.ReadLine();
            }
#endif
                Logger.Info("Thanks for playing!");

                // Use our thread exit code as our app exit code so we can check for errors easily
                return Result.ExitCode;


            } catch (Exception e)
            {
                Logger.Error($"Error! {e}");
                return -1;
            }

        }

       
    }
    public static class Logger
    {
        public enum LogLevels
        {
            ERROR,
            INFO,
            DEBUG
        }

        public static LogLevels Level { get; set; } = LogLevels.INFO;


        static Logger()
        {

        }

        public static void Debug(string Message)
        {
            var methodInfo = new StackTrace().GetFrame(1).GetMethod();
            var className = methodInfo.ReflectedType.Name;
            if (Level >= LogLevels.DEBUG) Console.WriteLine($"[=] [{className}:{methodInfo}] {Message}");
        }

        public static void Info(string Message)
        {
            if (Level >= LogLevels.INFO) Console.WriteLine($"[*] {Message}");
        }

        public static void Error(string Message)
        {
            if (Level >= LogLevels.ERROR) Console.WriteLine($"[!!] {Message}");
        }
    }
}
