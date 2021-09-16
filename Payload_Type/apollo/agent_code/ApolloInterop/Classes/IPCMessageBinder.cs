using ApolloInterop.Structs.ApolloStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace ApolloInterop.Classes
{
    public class IPCMessageBinder : SerializationBinder
    {
        public override Type BindToType(string assemblyName, string typeName)
        {
            if (typeName == "ApolloInterop.Structs.ApolloStructs.IPCData")
            {
                return typeof(IPCData);
            } else
            {
                throw new Exception($"Unexpected type: {typeName}");
            }
        }
    }
}
