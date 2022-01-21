using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Types;

namespace ApolloInterop.Serializers
{
    public class EncryptedJsonSerializer : JsonSerializer, ICryptographySerializer
    {
        private ICryptography Cryptor;
        public EncryptedJsonSerializer(ICryptography crypto) : base()
        {
            Cryptor = crypto;
        }

        public bool UpdateUUID(string uuid)
        {
            return Cryptor.UpdateUUID(uuid);
        }

        public bool UpdateKey(string key)
        {
            return Cryptor.UpdateKey(key);
        }

        public string GetUUID()
        {
            return Cryptor.GetUUID();
        }
        public override string Serialize(object msg)
        {
            string jsonMsg = base.Serialize(msg);
            return Cryptor.Encrypt(jsonMsg);
        }

        public override T Deserialize<T>(string msg) 
        {
            string decrypted = Cryptor.Decrypt(msg);
            return base.Deserialize<T>(decrypted);
        }

        public override object Deserialize(string msg, Type t)
        {
            string decrypted = Cryptor.Decrypt(msg);
            return base.Deserialize(decrypted, t);
        }

        public override IPCChunkedData[] SerializeIPCMessage(IMythicMessage message, int blockSize = 4096)
        {
            string msg = Serialize(message);
            byte[] bMsg = Encoding.UTF8.GetBytes(msg);
            int numMessages = bMsg.Length / blockSize + 1;
            IPCChunkedData[] ret = new IPCChunkedData[numMessages];
            var t = message.GetTypeCode();
            string id = Guid.NewGuid().ToString();
            for (int i = 0; i < numMessages; i ++)
            {
                byte[] part = bMsg.Skip(i*blockSize).Take(blockSize).ToArray();
                ret[i] = new IPCChunkedData(id, message.GetTypeCode(), i+1, numMessages, part);
            }
            return ret;
        }

        public override IMythicMessage DeserializeIPCMessage(byte[] data, MessageType mt)
        {
            string enc = Encoding.UTF8.GetString(data);
            Type t = MythicTypes.GetMessageType(mt);
            return (IMythicMessage)Deserialize(enc, t);
        }
    }
}
