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
    public class EncryptedJsonSerializerTests
    {
        static string UUID = "1432d007-b468-4ead-a4ed-2e97ac6fa304";
        protected static string AesKey = "XmXjZVfbbKmNMGf65QJx9Vjv4teM/vHz2IOvYJNfIrI=";
        protected static PSKCryptography.PSKCryptographyProvider Crypto = new PSKCryptographyProvider(UUID, AesKey);
        static EncryptedJsonSerializer marshaller = new EncryptedJsonSerializer(Crypto);
        
        [TestMethod]
        public void TestUploadMessage()
        {
            string jsonMsg = marshaller.Serialize(Upload);

            UploadMessage tmp = marshaller.Deserialize<UploadMessage>(jsonMsg);

            Assert.AreEqual(Upload, tmp);
        }

        [TestMethod]
        public void TestCheckinMessage()
        {
            string actualCheckin = marshaller.Serialize(Checkin);
            CheckinMessage tmp = marshaller.Deserialize<CheckinMessage>(actualCheckin);
            Assert.AreEqual(Checkin, tmp);
        }

        [TestMethod]
        public void TestEdgeNodeMessage()
        {
            string jsonMsg = marshaller.Serialize(Node);
            Assert.AreEqual(Node, marshaller.Deserialize<EdgeNode>(jsonMsg));
        }

        [TestMethod]
        public void TestFileBrowserMessage()
        {
            string jsonmsg = marshaller.Serialize(Browser);
            var res = marshaller.Deserialize<FileBrowser>(jsonmsg);
            Assert.IsTrue(Browser.Equals(res));
        }

        [TestMethod]
        public void TestRemovedFileInformation()
        {
            string json = marshaller.Serialize(Removed);
            Assert.IsTrue(Removed.Equals(marshaller.Deserialize<RemovedFileInformation>(json)));
        }

        [TestMethod]
        public void TestCredential()
        {
            string j = marshaller.Serialize(Cred);
            Assert.IsTrue(Cred.Equals(marshaller.Deserialize<Credential>(j)));
        }

        [TestMethod]
        public void TestArtifact()
        {
            string j = marshaller.Serialize(ArtifactEx);
            Assert.IsTrue(ArtifactEx.Equals(marshaller.Deserialize<Artifact>(j)));
        }

        [TestMethod]
        public void TestFileInformation()
        {
            string jsonmsg = marshaller.Serialize(File);
            var result = marshaller.Deserialize<FileInformation>(jsonmsg);
            Assert.IsTrue(File.Equals(result));
        }

        [TestMethod]
        public void TestTaskingMessage()
        {

            string jsonMsg = marshaller.Serialize(Tasking);
            TaskingMessage tmp = marshaller.Deserialize<TaskingMessage>(jsonMsg);
            Assert.IsTrue(Tasking.Equals(tmp));
        }

        [TestMethod]
        public void TestTaskResponse()
        {
            string j = marshaller.Serialize(Response);
            Assert.IsTrue(Response.Equals(marshaller.Deserialize<TaskResponse>(j)));
        }

        [TestMethod]
        public void TestSocksDatagram()
        {
            string j = marshaller.Serialize(Datagram1);
            Assert.IsTrue(Datagram1.Equals(marshaller.Deserialize<SocksDatagram>(j)));
        }
    }
}
