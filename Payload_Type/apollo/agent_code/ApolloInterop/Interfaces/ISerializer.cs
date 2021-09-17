using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Structs.ApolloStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Interfaces
{
    public interface ISerializer
    {
        string Serialize(object obj);
        T Deserialize<T>(string msg);

        // This is so we can serialize/deserialize things across named pipes, but technically
        IPCChunkedData[] SerializeIPCMessage(IMythicMessage message, int block_size = 4096);
        IMythicMessage DeserializeIPCMessage(byte[] data, MessageType mt);
    }
}
