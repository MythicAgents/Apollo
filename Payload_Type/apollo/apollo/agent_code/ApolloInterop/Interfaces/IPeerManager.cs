﻿using ApolloInterop.Classes.P2P;
using ApolloInterop.Structs.MythicStructs;
namespace ApolloInterop.Interfaces
{
    public interface IPeerManager
    {
        Peer AddPeer(PeerInformation info);
        bool Remove(string uuid);
        bool Remove(IPeer peer);
        bool Route(DelegateMessage msg);
    }
}
