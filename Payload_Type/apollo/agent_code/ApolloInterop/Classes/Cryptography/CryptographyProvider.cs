using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using ApolloInterop.Interfaces;

namespace ApolloInterop.Classes
{
    abstract public class CryptographyProvider : ICryptography
    {
        public byte[] PSK { get; private set; }
        protected byte[] UUID { get; private set; }
        public bool UUIDUpdated { get; private set; } = false;

        public CryptographyProvider(string uuid, string key)
        {
            PSK = Convert.FromBase64String(key);
            UUID = ASCIIEncoding.ASCII.GetBytes(uuid);
        }

        // UUID should only be updated once after agent registration.
        public bool UpdateUUID(string uuid)
        {
            UUID = ASCIIEncoding.ASCII.GetBytes(uuid);
            UUIDUpdated = true;
            return true;
        }

        virtual public bool UpdateKey(string key)
        {
            PSK = Convert.FromBase64String(key);
            return true;
        }

        public virtual string GetUUID()
        {
            return ASCIIEncoding.ASCII.GetString(UUID);
        }

        public abstract string Encrypt(string plaintext);

        public abstract string Decrypt(string ciphertext);
    }
}
