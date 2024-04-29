using RunOF.Internals;
using System;
using System.Diagnostics;

namespace RunOF
{
    public class Program
    {
        public static string Main(string[] args)
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
            }
            catch (Exception e)
            {
                Logger.Error($"Unable to parse application arguments: \n {e}");
                return $"Error parsing arguments\n Exception: {e.Message} \n Location: {e.StackTrace}";
            }
            try
            {
                Logger.Info($"Loading object file {ParsedArgs.filename}");
                BofRunner bof_runner = new BofRunner(ParsedArgs);
                bof_runner.LoadBof();
                Logger.Info($"About to start BOF in new thread at {bof_runner.entry_point.ToInt64():X}");
                var Result = bof_runner.RunBof();
                //Console.WriteLine("------- BOF OUTPUT ------");
                //Console.WriteLine($"{Result.Output}");
                //Console.WriteLine("------- BOF OUTPUT FINISHED ------");
                return Result.Output;
            } 
            catch (Exception e)
            {
                Logger.Error($"Error! {e}");
                return $"Exception: {e}\n Location: {e.StackTrace}";
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

        [Conditional("DEBUG")]
        public static void Debug(string Message)
        {
            var methodInfo = new StackTrace().GetFrame(1).GetMethod();
            var className = methodInfo.ReflectedType.Name;
            if (Level >= LogLevels.DEBUG) Console.WriteLine($"[=] [{className}:{methodInfo}] {Message}");
        }

        [Conditional("DEBUG")]
        public static void Info(string Message)
        {
            if (Level >= LogLevels.INFO) Console.WriteLine($"[*] {Message}");
        }

        [Conditional("DEBUG")]
        public static void Error(string Message)
        {
            if (Level >= LogLevels.ERROR) Console.WriteLine($"[!!] {Message}");
        }
    }
}
