using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Interfaces
{
    public interface IPeer
    {
        void Start();
        void Stop();
        string GetUUID();
        string Connected();
        string ProcessMessage(DelegateMessage message);
        bool Finished();
    }
}
