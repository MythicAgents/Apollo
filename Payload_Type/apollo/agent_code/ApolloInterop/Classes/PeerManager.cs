using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes
{
    public abstract class PeerManager : IPeerManager
    {
        protected ConcurrentDictionary<string, IPeer> Peers = new ConcurrentDictionary<string, IPeer>();
        protected IAgent Agent;
        public PeerManager(IAgent agent)
        {
            Agent = agent;
        }

        public abstract IPeer AddSMBPeer(string pipename, IC2ProfileManager manager);
        public virtual bool Remove(string uuid)
        {
            return Peers.TryRemove(uuid, out var p);
        }

        public virtual bool Remove(IPeer peer)
        {
            return Peers.TryRemove(peer.GetUUID(), out var p);
        }

        public abstract bool Route(DelegateMessage msg);
    }
}
