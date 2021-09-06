using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using PlaintextCryptography;
using ApolloInterop.Structs;
using ApolloInterop.Serializers;

namespace HttpProfileTests
{
    [TestClass]
    public class HttpProfileTests
    {
        protected static Dictionary<string, string> parameters = new Dictionary<string, string>()
        {
            { "callback_interval", "1" },
            { "callback_jitter", "0" },
            { "callback_port", "80" },
            { "callback_host", "mythic" },
            { "post_uri", "/testendpoint" },
            { "encrypted_exchange_check", "F" },
            { "proxy_host", "127.0.0.1" },
            { "proxy_port", "8888" },
            { "proxy_user", "testuser" },
            { "proxy_pass", "testpassword" },
            { "domain_front", "test.front.com" },
            { "killdate", "01-01-1999" },
            { "USER_AGENT", "test-ua" }
        };

        protected static string UUID = "1432d007-b468-4ead-a4ed-2e97ac6fa304";

        protected static PlaintextCryptographyProvider Cryptor = new PlaintextCryptographyProvider(UUID, "");

        protected static EncryptedJsonSerializer Serializer = new EncryptedJsonSerializer(Cryptor);

        //protected static HttpTransport.HttpProfile profile = new HttpTransport.HttpProfile(parameters, Serializer);
        
        
    }
}
