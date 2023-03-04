using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Interfaces;
using System.IO;
using System.Runtime.Serialization.Json;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Types;
using ApolloInterop.Enums.ApolloEnums;
using System.Diagnostics;
using System.Reflection;
using ApolloInterop.Structs.MythicStructs;

namespace ApolloInterop.Serializers
{
    public class JsonSerializer : ISerializer
    {
        //List<Type> _knownTypes = new List<Type>();
        public JsonSerializer()
        {
            //Assembly interopAsm = Assembly.GetAssembly(typeof(TaskResponse));
            //foreach(Type t in interopAsm.GetTypes())
            //{
            //    if (t.FullName.StartsWith("ApolloInterop.Structs.MythicStructs") || t.FullName.StartsWith("ApolloInterop.Structs.ApolloStructs"))
            //    {
            //        _knownTypes.Add(t);
            //    }
            //}
        }

        public virtual string Serialize(object msg)
        {
            using (var ms = new MemoryStream())
            {
                var ser = new DataContractJsonSerializer(msg.GetType());
                ser.WriteObject(ms, msg);
                ms.Position = 0;
                using (var sr = new StreamReader(ms))
                {
                    string res = sr.ReadToEnd();
                    return res;
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

        public virtual object Deserialize(string msg, Type t)
        {
            using (var ms = new MemoryStream(Encoding.Unicode.GetBytes(msg)))
            {
                var deserializer = new DataContractJsonSerializer(t);
                return deserializer.ReadObject(ms);
            }
        }

        public virtual IPCChunkedData[] SerializeDelegateMessage(string message, MessageType mt, int blockSize = 4096)
        {
            // This delegate message is already encoding from Mythic, so we just need to get the bytes
            byte[] bMsg = Encoding.UTF8.GetBytes(message);
            int numMessages = bMsg.Length / blockSize + 1;
            IPCChunkedData[] ret = new IPCChunkedData[numMessages];
            string id = Guid.NewGuid().ToString();
            for (int i = 0; i < numMessages; i++)
            {
                byte[] part = bMsg.Skip(i * blockSize).Take(blockSize).ToArray();
                ret[i] = new IPCChunkedData(id, mt, i+1, numMessages, part);
            }
            return ret;
        }

        public virtual IPCChunkedData[] SerializeIPCMessage(IMythicMessage message, int blockSize = 4096)
        {
            string msg = Serialize(message);
            byte[] bMsg = Encoding.UTF8.GetBytes(msg);
            int numMessages = bMsg.Length / blockSize + 1;
            IPCChunkedData[] ret = new IPCChunkedData[numMessages];
            var t = message.GetTypeCode();
            string id = Guid.NewGuid().ToString();
            for (int i = 0; i < numMessages; i++)
            {
                byte[] part = bMsg.Skip(i * blockSize).Take(blockSize).ToArray();
                ret[i] = new IPCChunkedData(id, message.GetTypeCode(), i+1, numMessages, part);
            }
            return ret;
        }

        public virtual IMythicMessage DeserializeIPCMessage(byte[] data, MessageType mt)
        {
            string msg = Encoding.UTF8.GetString(data);
            Type t = MythicTypes.GetMessageType(mt);
            return (IMythicMessage)Deserialize(msg, t);
        }
    }
}
