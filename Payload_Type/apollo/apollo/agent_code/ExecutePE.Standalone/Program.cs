using System;
using System.IO;
using ApolloInterop.Structs.ApolloStructs;

namespace ExecutePE.Standalone;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine($"Executable not specified");
            return -1;
        }

        var executablePath = args[0];
        Console.WriteLine($"Executable: {executablePath}");

        var executable = File.ReadAllBytes(executablePath);

        var executableName = Path.GetFileName(executablePath);
        Console.WriteLine($"Executable name: {executableName}");;

        var peCommandLine = Environment.CommandLine.Substring(Environment.CommandLine.IndexOf(executableName));
        Console.WriteLine($"PE Command line: {peCommandLine}");

        var message = new ExecutePEIPCMessage()
        {
            Executable = executable,
            ImageName = executableName,
            CommandLine = peCommandLine,
        };

        PERunner.RunPE(message);
        return 0;
    }
}
