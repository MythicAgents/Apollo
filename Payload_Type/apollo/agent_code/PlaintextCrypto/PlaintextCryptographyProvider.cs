using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;

namespace PlaintextCryptography
{
    public class PlaintextCryptographyProvider : CryptographyProvider, ICryptography
    {
        private string UUID = "";
        private string Key = "";
        public PlaintextCryptographyProvider(string uuid, string key) : base(uuid, key)
        {
            if (string.IsNullOrEmpty(uuid))
                throw new Exception("Invalid parameters to PlaintextCrypto. Require non-null UUID.");
            UUID = uuid;
        }

        public bool UpdateUUID(string uuid)
        {
            throw new Exception("Operation not supported by PlaintextCryptographyProvider.");
        }

        public bool UpdateKey(string key)
        {
            throw new Exception("Operation is not supported by PlaintextCryptographyProvider.");
        }

        public string Encrypt(string plaintext)
        {
            return string.Format("{0}{1}", UUID, plaintext);
        }

        public string Decrypt(string enc)
        {
            if (!enc.StartsWith(UUID))
                throw new Exception("Invalid message received from server.");
            return enc.Substring(UUID.Length);
        }
    }
}
