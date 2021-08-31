using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Interfaces;

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
    }
}
