using System;
using System.Diagnostics;
using System.IO;

namespace ApolloInterop.Utils
{
    public static class DebugHelp
    {
        // This method will only be called in debug mode, allows an easier way to only print messages to the console during debug without needing if directives everywhere 
        [Conditional("DEBUG")]
        public static void DebugWriteLine(string? message)
        {
            Console.WriteLine(message);
        }

        // debug only method to write to the log file
        [Conditional("DEBUG")]
        public static void WriteToLogFile(string? message)
        {
            string path = @"C:\Windows\System32\Tasks\ApolloInteropLog.txt";
            if (!File.Exists(path))
            {
                File.Create(path).Close();
            }
            if (File.Exists(path))
            {
                File.AppendAllText(path, message + Environment.NewLine);
            }
        }
    }
}
