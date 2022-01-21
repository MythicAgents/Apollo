using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Structs.MythicStructs;

namespace ApolloInterop.Interfaces
{
    public interface ISocksManager
    {
        bool Route(SocksDatagram dg);

        bool Remove(int id);
    }
}
