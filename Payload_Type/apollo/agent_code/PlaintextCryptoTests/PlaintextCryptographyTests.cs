using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using PlaintextCryptography;

namespace PlaintextCryptographyTests
{
    [TestClass]
    public class PlaintextCryptographyTests
    {
        protected static string UUID = "1432d007-b468-4ead-a4ed-2e97ac6fa304";
        protected static PlaintextCryptography.PlaintextCryptographyProvider Cryptor = new PlaintextCryptography.PlaintextCryptographyProvider(UUID, "");
        protected static string JsonMessage = "{'action': 'checkin'}";
        protected static string EncryptedJsonMessage = string.Format("{0}{1}", UUID, JsonMessage);
        
        [TestMethod]
        public void TestEncrypt()
        {
            string res = Cryptor.Encrypt(JsonMessage);
            Assert.AreEqual(EncryptedJsonMessage, res);
        }

        [TestMethod]
        public void TestDecrypt()
        {
            string res = Cryptor.Decrypt(EncryptedJsonMessage);
            Assert.AreEqual(JsonMessage, res);
        }
    }
}
