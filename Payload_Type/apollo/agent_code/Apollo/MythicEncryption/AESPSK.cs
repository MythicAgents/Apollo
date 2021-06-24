using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace Mythic.Encryption
{
    /// <summary>
    /// Encryption handler for the Default profile type.
    /// </summary>
    /// <summary>
    /// Encryption handler for the Default profile type.
    /// </summary>
    class PSKCrypto : Crypto.Crypto
    {
        /// <summary>
        /// Pre-shared key given to us by God to identify
        /// ourselves to the mothership. When transferring
        /// C2 Profiles, thsi key must remain the same across
        /// Profile.Crypto classes.
        /// </summary>
        private byte[] PSK = { 0x00 };
        //private byte[] uuid;

        /// <summary>
        /// Instantiate a DefaultEncryption class
        /// </summary>
        /// <param name="pskString">The Pre-Shared Key in b64 format.</param>
        public PSKCrypto(string uuidString, string pskString)
        {
            PSK = Convert.FromBase64String(pskString);
            uuid = ASCIIEncoding.ASCII.GetBytes(uuidString);
        }

        /// <summary>
        /// Encrypt any given plaintext with the PSK given
        /// to the agent.
        /// </summary>
        /// <param name="plaintext">Plaintext to encrypt.</param>
        /// <returns>Enrypted string.</returns>
        override internal string Encrypt(string plaintext)
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
                    byte[] final = uuid.Concat(encrypted.Concat(hmac).ToArray()).ToArray();
                    // Return base64 encoded ciphertext
                    return Convert.ToBase64String(final);
                }
            }
        }

        /// <summary>
        /// Decrypt a string which has been encrypted with the PSK.
        /// </summary>
        /// <param name="encrypted">The encrypted string.</param>
        /// <returns></returns>
        override internal string Decrypt(string encrypted)
        {
            byte[] input = Convert.FromBase64String(encrypted); // FAILURE

            int uuidLength = uuid.Length;
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

        internal override void UpdateUUID(string newUUID)
        {
            uuid = ASCIIEncoding.ASCII.GetBytes(newUUID);
        }
    }
}
