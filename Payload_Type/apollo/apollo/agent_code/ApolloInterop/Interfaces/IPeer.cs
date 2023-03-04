using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Interfaces
{
    public interface IPeer
    {
        bool Start();
        void Stop();
        string GetUUID();
        string GetMythicUUID();
        bool Connected();
        void ProcessMessage(DelegateMessage message);
        bool Finished();
    }
}
