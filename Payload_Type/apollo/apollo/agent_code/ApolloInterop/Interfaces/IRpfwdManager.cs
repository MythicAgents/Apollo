using ApolloInterop.Structs.MythicStructs;
using System.Net.Sockets;
using ApolloInterop.Classes;

namespace ApolloInterop.Interfaces
{
    public interface IRpfwdManager
    {
        bool Route(SocksDatagram dg);
        bool AddConnection(TcpClient client, int ServerID, int port, int debugLevel, Tasking task);
        bool Remove(int id);
    }
}
