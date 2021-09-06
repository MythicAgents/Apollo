using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using ApolloInterop.Serializers;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Interfaces;
using PSKCryptography;
using static ApolloInteropTests.Structs;
namespace ApolloInteropTests
{
    [TestClass]
    public class EncryptedJsonSerializerTests : SerializerTestClass
    {
        static string UUID = "1432d007-b468-4ead-a4ed-2e97ac6fa304";
        protected static string AesKey = "XmXjZVfbbKmNMGf65QJx9Vjv4teM/vHz2IOvYJNfIrI=";
        protected static PSKCryptographyProvider Crypto = new PSKCryptographyProvider(UUID, AesKey);
        static EncryptedJsonSerializer marshaller = new EncryptedJsonSerializer(Crypto);
        
        public EncryptedJsonSerializerTests() : base(marshaller)
        {

        }
    }
}
