using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using ApolloInterop.Interfaces;

namespace ApolloInterop.Classes
{
    public abstract class C2ProfileManager : IC2ProfileManager 
    {
        protected IAgent Agent;
        protected ConcurrentBag<IC2Profile> EgressProfiles = new ConcurrentBag<IC2Profile>();
        protected ConcurrentBag<IC2Profile> IngressProfiles = new ConcurrentBag<IC2Profile>();

        public C2ProfileManager(IAgent agent)
        {
            Agent = agent;
        }

        public abstract IC2Profile NewC2Profile(Type c2, ISerializer serializer, Dictionary<string, string> parameters);

        public virtual bool AddEgress(IC2Profile profile)
        {
            EgressProfiles.Add(profile);
            return true;
        }

        public virtual bool AddIngress(IC2Profile profile)
        {
            IngressProfiles.Add(profile);
            return true;
        }

        public virtual IC2Profile[] GetEgressCollection()
        {
            return EgressProfiles.ToArray();
        }

        public virtual IC2Profile[] GetIngressCollection()
        {
            return IngressProfiles.ToArray();
        }

        public virtual IC2Profile[] GetConnectedEgressCollection()
        {
            List<IC2Profile> connected = new List<IC2Profile>();
            foreach(var c2 in EgressProfiles.ToArray())
            {
                if (c2.IsConnected())
                    connected.Add(c2);
            }
            return connected.ToArray();
        }
    }
}
