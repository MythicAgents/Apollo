using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes.P2P
{
    public abstract class PeerManager : IPeerManager
    {
        protected ConcurrentDictionary<string, IPeer> _peers = new ConcurrentDictionary<string, IPeer>();
        protected IAgent _agent;
        public PeerManager(IAgent agent)
        {
            _agent = agent;
        }

        public abstract Peer AddPeer(PeerInformation info);
        public virtual bool Remove(string uuid)
        {
            return _peers.TryRemove(uuid, out var p);
        }

        public virtual bool Remove(IPeer peer)
        {
            return _peers.TryRemove(peer.GetUUID(), out var p);
        }

        public abstract bool Route(DelegateMessage msg);
    }
}
