using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using System;
using System.Security.Cryptography;
using System.Linq;
using System.Text;
using System.IO;

namespace PSKCryptography
{
    public class PSKCryptographyProvider : CryptographyProvider, ICryptography
    {
        public PSKCryptographyProvider(string uuid, string key) : base(uuid, key)
        {
            
        }


        public override string Encrypt(string plaintext)
        {
            using (Aes scAes = Aes.Create())
            {
                // Use our PSK (generated in Apfell payload config) as the AES key
                scAes.Key = PSK;

                ICryptoTransform encryptor = scAes.CreateEncryptor(scAes.Key, scAes.IV);

                using (MemoryStream encryptMemStream = new MemoryStream())

                using (CryptoStream encryptCryptoStream = new CryptoStream(encryptMemStream, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter encryptStreamWriter = new StreamWriter(encryptCryptoStream))
                        encryptStreamWriter.Write(plaintext);
                    // We need to send uuid:iv:ciphertext:hmac
                    // Concat iv:ciphertext
                    byte[] encrypted = scAes.IV.Concat(encryptMemStream.ToArray()).ToArray();
                    HMACSHA256 sha256 = new HMACSHA256(PSK);
                    // Attach hmac to iv:ciphertext
                    byte[] hmac = sha256.ComputeHash(encrypted);
                    // Attach uuid to iv:ciphertext:hmac
                    byte[] final = UUID.Concat(encrypted.Concat(hmac).ToArray()).ToArray();
                    // Return base64 encoded ciphertext
                    return Convert.ToBase64String(final);
                }
            }
        }

        public override string Decrypt(string encrypted)
        {
            byte[] input = Convert.FromBase64String(encrypted); // FAILURE

            int uuidLength = UUID.Length;
            // Input is uuid:iv:ciphertext:hmac, IV is 16 bytes
            byte[] uuidInput = new byte[uuidLength];
            Array.Copy(input, uuidInput, uuidLength);

            byte[] IV = new byte[16];
            Array.Copy(input, uuidLength, IV, 0, 16);

            byte[] ciphertext = new byte[input.Length - uuidLength - 16 - 32];
            Array.Copy(input, uuidLength + 16, ciphertext, 0, ciphertext.Length);

            HMACSHA256 sha256 = new HMACSHA256(PSK);
            byte[] hmac = new byte[32];
            Array.Copy(input, uuidLength + 16 + ciphertext.Length, hmac, 0, 32);

            if (Convert.ToBase64String(hmac) == Convert.ToBase64String(sha256.ComputeHash(IV.Concat(ciphertext).ToArray())))
            {
                using (Aes scAes = Aes.Create())
                {
                    // Use our PSK (generated in Apfell payload config) as the AES key
                    scAes.Key = PSK;

                    ICryptoTransform decryptor = scAes.CreateDecryptor(scAes.Key, IV);

                    using (MemoryStream decryptMemStream = new MemoryStream(ciphertext))
                    using (CryptoStream decryptCryptoStream = new CryptoStream(decryptMemStream, decryptor, CryptoStreamMode.Read))
                    using (StreamReader decryptStreamReader = new StreamReader(decryptCryptoStream))
                    {
                        string decrypted = decryptStreamReader.ReadToEnd();
                        // Return decrypted message from Apfell server
                        return decrypted;
                    }
                }
            }
            else
            {
                throw new Exception("WARNING: HMAC did not match message!");
            }
        }
    }
}
