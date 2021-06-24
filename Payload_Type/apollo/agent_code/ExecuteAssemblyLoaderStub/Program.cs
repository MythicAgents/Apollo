using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.AccessControl;
using System.Text;
using System.Globalization;
using System.Reflection;
using System.Threading;
using IPC;
using System.IO;

namespace ExecuteAssemblyLoaderStub
{
    class Program
    {

        public static AssemblyJobMessage ReadJob(NamedPipeServerStream pipeServer)
        {
            // Method 1
            BinaryFormatter bf = new BinaryFormatter();
            bf.Binder = new AssemblyJobMessageBinder();
            var message = (AssemblyJobMessage)bf.Deserialize(pipeServer);
            return message;
        }

        public static NamedPipeServerStream CreateNamedPipeServer(string pipeName)
        {
            PipeSecurity pipeSecurityDescriptor = new PipeSecurity();
            PipeAccessRule everyoneAllowedRule = new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow);
            PipeAccessRule networkDenyRule = new PipeAccessRule("Network", PipeAccessRights.ReadWrite, AccessControlType.Deny);       // This should only be used locally, so lets limit the scope
            pipeSecurityDescriptor.AddAccessRule(everyoneAllowedRule);
            pipeSecurityDescriptor.AddAccessRule(networkDenyRule);

            // Gotta be careful with the buffer sizes. There's a max limit on how much data you can write to a pipe in one sweep. IIRC it's ~55,000, but I dunno for sure.
            NamedPipeServerStream pipeServer = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 10, PipeTransmissionMode.Byte, PipeOptions.None, 32768, 32768, pipeSecurityDescriptor);

            return pipeServer;
        }

        public static void InitializeNamedPipeServer(string pipeName)
        {
            NamedPipeServerStream pipeServer = CreateNamedPipeServer(pipeName);

            if (pipeServer == null)
                return;

            AssemblyJobMessage newJob = null;
            try
            {
                // We shouldn't need to go async here since we'll only have one client, the agent core, and it'll maintain the connection to the named pipe until the job is done
                pipeServer.WaitForConnection();

                //Console.WriteLine("Client connected");
                newJob = ReadJob(pipeServer);

            }
            catch (Exception e)
            {
                // Can't really return this error to the agent, so we're just going to have to abort everything
                // Console.WriteLine("ERROR: Could not read assembly from named pipe. " + e);
                if (pipeServer.IsConnected)
                    try
                    {
                        pipeServer.Close();
                    }
                    catch { };
                return;
            }


            var assembly = Assembly.Load(newJob.AssemblyBytes);
            //Console.WriteLine(assembly.FullName);

            using (StreamWriter writer = new StreamWriter(pipeServer))
            {
                writer.AutoFlush = true;

                var origStdout = Console.Out;
                var origStderr = Console.Error;

                Console.SetOut(writer);
                Console.SetError(writer);

                try
                {
                    assembly.EntryPoint.Invoke(null, new object[] { newJob.Args });
                }
                catch (Exception e)
                {
                    Console.WriteLine("ERROR: Unhandled exception in the assembly " + assembly.FullName + ":");
                    Console.WriteLine(e);
                }
                finally
                {
                    // Restore streams... probably don't need to do this but meh
                    Console.SetOut(origStdout);
                    Console.SetError(origStderr);
                }

                pipeServer.WaitForPipeDrain();
            }

            if (pipeServer.IsConnected)
                try
                {
                    pipeServer.Close();
                } catch { }
            //Console.WriteLine("Waiting for output to be read completely...");
            //Console.WriteLine("Exiting loader stub...");
        }

        static void Main(string[] args)
        {
#if DEBUG
            InitializeNamedPipeServer("HelloWorld");
#endif
        }
    }
}
