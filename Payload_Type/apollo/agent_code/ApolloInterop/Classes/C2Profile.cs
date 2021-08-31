using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs;
using System.IO;
using System.Runtime.Serialization.Json;

namespace ApolloInterop.Classes
{
    public abstract class C2Profile
    {
        protected const int MAX_RETRIES = 10;
        protected ISerializer Serializer;
        public C2Profile(Dictionary<string, string> parameters, ISerializer serializer)
        {
            Serializer = serializer;
        }
    }
}
