using ApolloInterop.Enums.ApolloEnums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Types
{
    namespace Delegates
    {
        public delegate bool OnResponse<T>(T message);
        public delegate bool DispatchMessage(byte[] data, MessageType mt);
    }
}
