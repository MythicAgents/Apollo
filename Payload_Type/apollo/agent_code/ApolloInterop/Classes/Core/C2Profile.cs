using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Collections.Concurrent;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Types.Delegates;
using ApolloInterop.Classes.Core;

namespace ApolloInterop.Classes
{
    public abstract class C2Profile
    {
        protected const int MAX_RETRIES = 10;
        protected ISerializer Serializer;
        protected IAgent Agent;
        protected bool Connected = false;
        protected ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>> MessageStore = new ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>>();
        public C2Profile(Dictionary<string, string> parameters, ISerializer serializer, IAgent agent)
        {
            Agent = agent;
            Serializer = serializer;
        }
    }
}
