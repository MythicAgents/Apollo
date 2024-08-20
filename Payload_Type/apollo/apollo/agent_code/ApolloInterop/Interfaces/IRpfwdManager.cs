using ApolloInterop.Structs.MythicStructs;
using System.Net.Sockets;

namespace ApolloInterop.Interfaces
{
    public interface IRpfwdManager
    {
        bool Route(SocksDatagram dg);
        bool AddConnection(TcpClient client, int ServerID, int port);
        bool Remove(int id);
    }
}
