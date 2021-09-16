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
            const string namedpipename = "djh-test";
            DummyCallback dc = new DummyCallback();
            AsyncNamedPipeServer server = new AsyncNamedPipeServer(namedpipename, dc, null, 2);

            IPCData serverSendData = new IPCData();
            for(int i = 0; i < 10; i ++)
            {
                AsyncNamedPipeClient client = new AsyncNamedPipeClient(".", namedpipename);
                Thread t = new Thread(() =>
                { 
                    try
                    {
                        PipeStream pipe = client.Connect(10000);
                        string message = "test request " + i.ToString();
                        byte[] output = Encoding.UTF8.GetBytes(message);
                        pipe.Write(output, 0, output.Length);

                        byte[] data = new byte[4096];
                        int bytesRead = pipe.Read(data, 0, data.Length);

                        Console.WriteLine(Encoding.UTF8.GetString(data, 0, bytesRead));
                    } catch (Exception ex)
                    {
                        Console.WriteLine(i.ToString() + " exception: " + ex.Message);
                    }
                });
                t.Start();
            }
            server.Stop();
            //Agent.Apollo ap = new Agent.Apollo(Config.PayloadUUID);
            //ap.Start();
            //Console.WriteLine();
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
