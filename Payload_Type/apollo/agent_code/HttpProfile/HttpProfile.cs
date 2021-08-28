using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using static ApolloInterop.Structs.MythicStructs;
using System.Net;

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

        ICryptography Cryptor;

        public HttpProfile(C2ProfileData data, ICryptography crypto) : base(data, crypto)
        {
            CallbackInterval = int.Parse(data.parameters["callback_interval"]) * 1000;
            CallbackJitter = int.Parse(data.parameters["callback_jitter"]);
            CallbackPort = int.Parse(data.parameters["callback_port"]);
            CallbackHost = data.parameters["callback_host"];
            PostUri = data.parameters["post_uri"];
            EncryptedExchangeCheck = data.parameters["encrypted_exchange_check"] == "T";
            ProxyHost = data.parameters["proxy_host"];
            ProxyPort = data.parameters["proxy_port"];
            ProxyAddress = string.Format("{0}:{1}", ProxyHost, ProxyPort);
            ProxyUser = data.parameters["proxy_user"];
            ProxyPass = data.parameters["proxy_pass"];
            DomainFront = data.parameters["domain_front"];
            KillDate = data.parameters["killdate"];
            UserAgent = data.parameters["USER_AGENT"];
            Cryptor = crypto;
            
        }
    }
}
