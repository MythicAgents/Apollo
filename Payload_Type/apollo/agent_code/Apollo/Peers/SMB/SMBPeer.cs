using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AI = ApolloInterop;

namespace Apollo.Peers.SMB
{
    public class SMBPeer : AI.Classes.Peer
    {
        public SMBPeer(IAgent agent, IC2Profile c2) : base(agent, c2)
        {

        }

        public override string Connected()
        {
            throw new NotImplementedException();
        }

        public override bool Finished()
        {
            throw new NotImplementedException();
        }

        public override string ProcessMessage(DelegateMessage message)
        {
            throw new NotImplementedException();
        }

        public override void Start()
        {
            throw new NotImplementedException();
        }

        public override void Stop()
        {
            throw new NotImplementedException();
        }
    }
}
