using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using ApolloInterop.Serializers;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Interfaces;
using PSKCryptography;
using static ApolloInteropTests.Structs;

namespace ApolloInteropTests
{
    [TestClass]
    public class JsonSerializerTests : SerializerTestClass
    {
        static JsonSerializer marshaller = new JsonSerializer();
        public JsonSerializerTests() : base(marshaller)
        {
        }
    }

}
