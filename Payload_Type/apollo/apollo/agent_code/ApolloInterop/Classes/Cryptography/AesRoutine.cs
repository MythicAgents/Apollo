using System.IO;
using System.Security.Cryptography;
using ApolloInterop.Interfaces;

namespace ApolloInterop.Classes.Cryptography
{
    public class AesRoutine : ICryptographicRoutine
    {
        private readonly Aes _aes;
        
        public AesRoutine()
        {
            _aes = Aes.Create();
        }

        public AesRoutine(Aes aes)
        {
            _aes = aes;
        }
        
        public byte[] Encrypt(byte[] plaintext)
        {
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = _aes.Key;
                aesAlg.IV = _aes.IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plaintext, 0, plaintext.Length);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        public byte[] Decrypt(byte[] encrypted)
        {
            byte[] plaintext;
            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = _aes.Key;
                aesAlg.IV = _aes.IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(encrypted))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
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
        
    }
}