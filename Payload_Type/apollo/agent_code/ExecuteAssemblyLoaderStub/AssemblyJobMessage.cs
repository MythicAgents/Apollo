using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace IPC
{
    [Serializable]
    class AssemblyJobMessage
    {
        public byte[] AssemblyBytes;
        public string[] Args;
    }

    public class AssemblyJobMessageBinder : SerializationBinder
    {
        public override Type BindToType(string assemblyName, string typeName)
        {
            // One way to discover expected types is through testing deserialization
            // of **valid** data and logging the types used.
#if DEBUG
            Console.WriteLine($"BindToType('{assemblyName}', '{typeName}')");
#endif
            if (typeName == "IPC.AssemblyJobMessage")
            {
                return typeof(AssemblyJobMessage);
            }
            else
            {
                throw new ArgumentException("Unexpected type", nameof(typeName));
            }
        }
    }
}
