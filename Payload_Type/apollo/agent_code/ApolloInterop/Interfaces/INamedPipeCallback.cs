using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO.Pipes;
using ApolloInterop.Structs.ApolloStructs;

namespace ApolloInterop.Interfaces
{
    public interface INamedPipeCallback
    {
        void OnAsyncConnect(PipeStream pipe, out Object state);
        void OnAsyncDisconnect(PipeStream pipe, Object state);
        void OnAsyncMessageReceived(PipeStream pipe, IPCData data, Object state);
    }
}
