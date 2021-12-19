using ApolloInterop.Interfaces;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Crypto = System.Security.Cryptography;
using System.Text;
using ApolloInterop.Classes;

namespace EncryptedFileStore.Aes
{
    public class AesFileStore : EncryptedFileStore
    {
        private Crypto.Aes _aes;
        private byte[] _psk;
        public AesFileStore(IAgent agent) : base(agent)
        {
            _aes = System.Security.Cryptography.Aes.Create();
        }

        private byte[] Encrypt(byte[] plaintext)
        {
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Crypto.Aes aesAlg = Crypto.Aes.Create())
            {
                aesAlg.Key = _aes.Key;
                aesAlg.IV = _aes.IV;

                // Create an encryptor to perform the stream transform.
                Crypto.ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (Crypto.CryptoStream csEncrypt = new Crypto.CryptoStream(msEncrypt, encryptor, Crypto.CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plaintext, 0, plaintext.Length);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        private byte[] Decrypt(byte[] encrypted)
        {
            byte[] plaintext;
            // Create an Aes object
            // with the specified key and IV.
            using (Crypto.Aes aesAlg = Crypto.Aes.Create())
            {
                aesAlg.Key = _aes.Key;
                aesAlg.IV = _aes.IV;

                // Create a decryptor to perform the stream transform.
                Crypto.ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(encrypted))
                {
                    using (Crypto.CryptoStream csDecrypt = new Crypto.CryptoStream(msDecrypt, decryptor, Crypto.CryptoStreamMode.Read))
                    {
                        using (BinaryReader brDecrypt = new BinaryReader(csDecrypt))
                        {
                            plaintext = brDecrypt.ReadBytes((int)msDecrypt.Length);
                        }
                    }
                }
            }

            return plaintext;
        }
        
        public override string GetScript()
        {
            return Encoding.UTF8.GetString(Decrypt(_currentScript));
        }

        public override void SetScript(string script)
        {
            SetScript(Encoding.UTF8.GetBytes(script));
        }

        public override void SetScript(byte[] script)
        {
            _currentScript = Encrypt(script);
        }

        public override bool TryAddOrUpdate(string keyName, byte[] data)
        {
            byte[] enc = Encrypt(data);
            return _fileStore.TryAdd(keyName, enc);
        }

        public override bool TryGetValue(string keyName, out byte[] data)
        {
            if(_fileStore.TryGetValue(keyName, out data))
            {
                data = Decrypt(data);
                return true;
            }

            return false;
        }
    }
}