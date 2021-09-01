using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using static ApolloInteropTests.Structs;

namespace ApolloInteropTests
{
    public abstract class SerializerTestClass
    {
        ISerializer marshaller;

        public SerializerTestClass(ISerializer ser)
        {
            marshaller = ser;
        }

        [TestMethod]
        virtual public void TestUploadMessage()
        {
            string jsonMsg = marshaller.Serialize(Upload);

            UploadMessage tmp = marshaller.Deserialize<UploadMessage>(jsonMsg);

            Assert.AreEqual(Upload, tmp);
        }

        [TestMethod]
        virtual public void TestCheckinMessage()
        {
            string actualCheckin = marshaller.Serialize(Checkin);
            CheckinMessage tmp = marshaller.Deserialize<CheckinMessage>(actualCheckin);
            Assert.AreEqual(Checkin, tmp);
        }

        [TestMethod]
        virtual public void TestEdgeNodeMessage()
        {
            string jsonMsg = marshaller.Serialize(Node);
            Assert.AreEqual(Node, marshaller.Deserialize<EdgeNode>(jsonMsg));
        }

        [TestMethod]
        virtual public void TestFileBrowserMessage()
        {
            string jsonmsg = marshaller.Serialize(Browser);
            var res = marshaller.Deserialize<FileBrowser>(jsonmsg);
            Assert.IsTrue(Browser.Equals(res));
        }

        [TestMethod]
        virtual public void TestRemovedFileInformation()
        {
            string json = marshaller.Serialize(Removed);
            Assert.IsTrue(Removed.Equals(marshaller.Deserialize<RemovedFileInformation>(json)));
        }

        [TestMethod]
        virtual public void TestCredential()
        {
            string j = marshaller.Serialize(Cred);
            Assert.IsTrue(Cred.Equals(marshaller.Deserialize<Credential>(j)));
        }

        [TestMethod]
        virtual public void TestArtifact()
        {
            string j = marshaller.Serialize(ArtifactEx);
            Assert.IsTrue(ArtifactEx.Equals(marshaller.Deserialize<Artifact>(j)));
        }

        [TestMethod]
        virtual public void TestFileInformation()
        {
            string jsonmsg = marshaller.Serialize(File);
            var result = marshaller.Deserialize<FileInformation>(jsonmsg);
            Assert.IsTrue(File.Equals(result));
        }

        [TestMethod]
        virtual public void TestTaskingMessage()
        {

            string jsonMsg = marshaller.Serialize(Tasking);
            TaskingMessage tmp = marshaller.Deserialize<TaskingMessage>(jsonMsg);
            Assert.IsTrue(Tasking.Equals(tmp));
        }

        [TestMethod]
        virtual public void TestTaskResponse()
        {
            string j = marshaller.Serialize(Response);
            Assert.IsTrue(Response.Equals(marshaller.Deserialize<TaskResponse>(j)));
        }

        [TestMethod]
        virtual public void TestSocksDatagram()
        {
            string j = marshaller.Serialize(Datagram1);
            Assert.IsTrue(Datagram1.Equals(marshaller.Deserialize<SocksDatagram>(j)));
        }

        [TestMethod]
        virtual public void TestMessageResponse()
        {
            string j = marshaller.Serialize(Message);
            Assert.AreEqual(Message, marshaller.Deserialize<MessageResponse>(j));
        }
    }
}
