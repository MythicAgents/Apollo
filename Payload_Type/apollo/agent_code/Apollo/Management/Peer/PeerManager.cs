using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using AI = ApolloInterop;
namespace Apollo.Management.Peer
{
    public class PeerManager : AI.Classes.PeerManager
    {
        public PeerManager(IAgent agent) : base(agent)
        {

        }

        public override IPeer AddSMBPeer(string pipename, IC2ProfileManager manager)
        {
            throw new NotImplementedException();
        }

        public override bool Route(DelegateMessage msg)
        {
            if (Peers.ContainsKey(msg.UUID))
            {
                // ???
                Peers[msg.UUID].ProcessMessage(msg);
                return true;
            }
            return false;
        }
    }
}
