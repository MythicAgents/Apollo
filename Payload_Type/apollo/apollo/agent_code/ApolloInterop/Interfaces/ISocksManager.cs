using ApolloInterop.Structs.MythicStructs;

namespace ApolloInterop.Interfaces
{
    public interface ISocksManager
    {
        bool Route(SocksDatagram dg);

        bool Remove(int id);
    }
}
