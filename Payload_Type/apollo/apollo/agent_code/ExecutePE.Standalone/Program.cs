using System;
using System.IO;
using System.Runtime.Remoting.Messaging;
using System.Threading;
using ApolloInterop.Structs.ApolloStructs;
using static ExecutePE.PERunner;

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



        //var memoryPE = new PERunner.MemoryPE(executable, peCommandLine);
        //memoryPE.ExecuteInThread(true, -1);

            //PERunner.RunPE(peMessage);
            // Set up API hooking for console functions
            using (ExitInterceptor interceptor = new ExitInterceptor())
            {
                // Apply the patches before loading and running the PE
                if (interceptor.ApplyExitFunctionPatches())
                {
                    using (PERunner.MemoryPE memoryPE = new PERunner.MemoryPE(executable, peCommandLine))
                    {
                        // Create a wait handle to signal when execution is complete
                        var executionCompletedEvent = new ManualResetEvent(false);

                        // Execute the PE in a separate thread to avoid blocking the main thread
                        //Console.WriteLine("\nExecuting PE file in a separate thread...");
                        //Stopwatch sw = Stopwatch.StartNew();

                        ThreadPool.QueueUserWorkItem(_ =>
                        {
                            try
                            {
                                // You can either use Execute() or ExecuteInThread()
                                Console.WriteLine("[*] Calling PE entry point...");
                                int? return_code = memoryPE.ExecuteInThread(waitForExit: true);
                                Console.WriteLine($"\n[*] PE function returned with exit code: {return_code}");
                                //Thread.Sleep(5000);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"\nError during PE execution: {ex.Message}");
                            }
                            finally
                            {
                                // Signal completion regardless of outcome
                                Console.WriteLine("in finally calling executionCompletedEvent");
                                executionCompletedEvent.Set();
                                Console.WriteLine("finishing ThreadPool work item");
                            }
                        });

                        // Wait for either completion or cancellation
                        // Console.WriteLine("Waiting for PE execution to complete...");

                        // Create an array of wait handles to wait for
                        WaitHandle[] waitHandles = new WaitHandle[]
                        {
                                    executionCompletedEvent,         // PE execution completed
                        };

                    // Wait for any of the handles to be signaled
                    Console.WriteLine("waiting for executionCompletedEvent to trigger");
                        int signalIndex = WaitHandle.WaitAny(waitHandles);
                    }
                Console.WriteLine("about to remove exit hooks");
                    bool removedHooks = interceptor.RemoveExitFunctionPatches();
                Console.WriteLine($"removed exit hooks: {removedHooks}");
                }
                else
                {
                    Console.WriteLine("Failed to apply exit function patches");
                }
            }
        Console.WriteLine("returning 0 from main program");
        return 0;
    }
}
