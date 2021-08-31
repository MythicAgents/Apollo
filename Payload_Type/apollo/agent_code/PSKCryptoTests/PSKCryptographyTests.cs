using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using PSKCryptography;

namespace PSKCryptographyTests
{
    [TestClass]
    public class PSKCryptographyTests
    {
        protected static string UUID = "1432d007-b468-4ead-a4ed-2e97ac6fa304";
        protected static string AesKey = "XmXjZVfbbKmNMGf65QJx9Vjv4teM/vHz2IOvYJNfIrI=";
        protected static PSKCryptographyProvider Cryptor = new PSKCryptographyProvider(UUID, AesKey);
        protected static string JsonMessage = "{'action': 'checkin'}";
        
        // Unfortunately, we need to do both encrypt and decrypt
        // in the same function as initialization vectors are instantiated
        // each time you encrypt.
        [TestMethod]
        public void TestEncryptAndDecrypt()
        {
            string enc = Cryptor.Encrypt(JsonMessage);
            string dec = Cryptor.Decrypt(enc);
            Assert.AreEqual(JsonMessage, dec);
        }
    }
}
