using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Interfaces;
using System.IO;
using System.Runtime.Serialization.Json;

namespace ApolloInterop.Serializers
{
    public class JsonSerializer : ISerializer
    {
        public JsonSerializer() { }

        public virtual string Serialize(object msg)
        {
            using (var ms = new MemoryStream())
            {
                var ser = new DataContractJsonSerializer(msg.GetType());
                ser.WriteObject(ms, msg);
                ms.Position = 0;
                using (var sr = new StreamReader(ms))
                {
                    return sr.ReadToEnd();
                }
            }
        }

        public virtual T Deserialize<T>(string msg)
        {
            using (var ms = new MemoryStream(Encoding.Unicode.GetBytes(msg)))
            {
                var deserializer = new DataContractJsonSerializer(typeof(T));
                return (T)deserializer.ReadObject(ms);
            }
        }
    }
}
