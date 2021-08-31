using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using ApolloInterop.Serializers;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Interfaces;
using PSKCryptography;
namespace ApolloInteropTests
{
    [TestClass]
    public class JsonSerializerTests
    {
        static JsonSerializer marshaller = new JsonSerializer();
        static string UUID = "1432d007-b468-4ead-a4ed-2e97ac6fa304";
        
        [TestMethod]
        public void TestUploadMessage()
        {
            UploadMessage msg = new UploadMessage()
            {
                ChunkNumber = 0,
                ChunkSize = 1,
                FileID = "test",
                FullPath = "testpath",
                TaskID = "taskid",
            };
            string jsonMsg = marshaller.Serialize(msg);

            UploadMessage tmp = marshaller.Deserialize<UploadMessage>(jsonMsg);

            Assert.AreEqual(msg, tmp);
        }

        [TestMethod]
        public void TestCheckinMessage()
        {
            CheckinMessage msg = new CheckinMessage()
            {
                Action = "checkin",
                OS = "Windows",
                User = "tester",
                Host = "test_host",
                PID = 10,
                IP = "127.0.0.1",
                UUID = UUID,
                Architecture = "x64",
                Domain = "TESTDOMAIN",
                IntegrityLevel = IntegrityLevel.HighIntegrity,
                ExternalIP = "99.99.99.99",
                EncryptionKey = "TEST_ENC_KEY",
                DecryptionKey = "TEST_DEC_KEY",
                PublicKey = "TEST_PUB_KEY",
                SessionID = "TESTSESSION"
            };

            string actualCheckin = marshaller.Serialize(msg);
            
            CheckinMessage tmp = marshaller.Deserialize<CheckinMessage>(actualCheckin);
            Assert.AreEqual(msg, tmp);
        }

        [TestMethod]
        public void TestEdgeNodeMessage()
        {
            var node = new EdgeNode()
            {
                Source = "test-source",
                Destination = "test-dest",
                Direction = EdgeDirection.SourceToDestination,
                MetaData = "test-meta",
                Action = "test-action",
                C2Profile = "test-c2profile"
            };
            string jsonMsg = marshaller.Serialize(node);
            Assert.AreEqual(node, marshaller.Deserialize<EdgeNode>(jsonMsg));
        }

        [TestMethod]
        public void TestFileBrowserMessage()
        {
            var fb = new FileBrowser()
            {
                Host = "127.0.0.1",
                IsFile = true,
                Permissions = new Dictionary<string, string>() { { "test-perm", "test-perm-val" } },
                Name = "test-name",
                ParentPath = "parent-path",
                Success = true,
                AccessTime = "accesstime",
                ModifyTime = "mod",
                Size = 100,
                Files = new FileInformation[1]
                {
                    new FileInformation()
                    {
                        FullName = "fullname",
                        Name = "name",
                        Directory = "dir",
                        CreationDate = "cd",
                        ModifyTime = "mt",
                        AccessTime = "at",
                        Permissions = new Dictionary<string, string>()
                        {
                            { "test-perm2", "test-perm2-val" },
                        },
                        ExtendedAttributes = "ea",
                        Size = 200,
                        Owner = "owner",
                        Group = "grp",
                        Hidden = false,
                        IsFile = true,
                    }
                },
            };

            string jsonmsg = marshaller.Serialize(fb);
            var res = marshaller.Deserialize<FileBrowser>(jsonmsg);
            Assert.AreEqual(fb.Host, res.Host);
            Assert.AreEqual(fb.IsFile, res.IsFile);
            Assert.AreEqual(fb.Permissions["test-perm"], res.Permissions["test-perm"]);
            Assert.AreEqual(fb.Name, res.Name);
            Assert.AreEqual(fb.ParentPath, res.ParentPath);
            Assert.AreEqual(fb.Success, res.Success);
            Assert.AreEqual(fb.AccessTime, res.AccessTime);
            Assert.AreEqual(fb.ModifyTime, res.ModifyTime);
            Assert.AreEqual(fb.Size, res.Size);
            Assert.AreEqual(fb.Files[0].Permissions["test-perm2"], res.Files[0].Permissions["test-perm2"]);
            Assert.AreEqual(fb.Files[0].FullName, res.Files[0].FullName);
            Assert.AreEqual(fb.Files[0].Name, res.Files[0].Name);
            Assert.AreEqual(fb.Files[0].Directory, res.Files[0].Directory);
            Assert.AreEqual(fb.Files[0].CreationDate, res.Files[0].CreationDate);
            Assert.AreEqual(fb.Files[0].ModifyTime, res.Files[0].ModifyTime);
            Assert.AreEqual(fb.Files[0].AccessTime, res.Files[0].AccessTime);
            Assert.AreEqual(fb.Files[0].ExtendedAttributes, res.Files[0].ExtendedAttributes);
            Assert.AreEqual(fb.Files[0].Size, res.Files[0].Size);
            Assert.AreEqual(fb.Files[0].Owner, res.Files[0].Owner);
            Assert.AreEqual(fb.Files[0].Group, res.Files[0].Group);
            Assert.AreEqual(fb.Files[0].Hidden, res.Files[0].Hidden);
            Assert.AreEqual(fb.Files[0].IsFile, res.Files[0].IsFile);
        }

        [TestMethod]
        public void TestTaskingMessage()
        {
            Dictionary<string, string> test = new Dictionary<string, string>()
            {
                { "delegate1_key", "delegate1_val" }
            };
            Dictionary<string, string> test2 = new Dictionary<string, string>()
            {
                { "delegat2_key", "delegate2_val" }
            };
            TaskResponse[] taskResponses = new TaskResponse[1]
            {
                new TaskResponse()
                {
                    UserOutput = "out1",
                    Completed = true,
                    User = "testuser",
                    WindowTitle = "newtitle",
                    Keystrokes = "asdf",
                    TaskID = "test-id",
                    Status = StatusMessage.Complete.ToString(),
                    Edges = new EdgeNode[1]
                    {
                        new EdgeNode()
                        {
                            Source = "test-source",
                            Destination = "test-dest",
                            Direction = EdgeDirection.SourceToDestination,
                            MetaData = "test-meta",
                            Action = "test-action",
                            C2Profile = "test-c2profile"
                        }
                    },
                    FileBrowser = new FileBrowser()
                    {
                        Host = "127.0.0.1",
                        IsFile = true,
                        Permissions = new Dictionary<string, string>() { { "test-perm", "test-perm-val" } },
                        Name = "test-name",
                        ParentPath = "parent-path",
                        Success = true,
                        AccessTime = "accesstime",
                        ModifyTime = "mod",
                        Size = 100,
                        Files = new FileInformation[1]
                        {
                            new FileInformation()
                            {
                                FullName = "fullname",
                                Name = "name",
                                Directory = "dir",
                                CreationDate = "cd",
                                ModifyTime = "mt",
                                AccessTime = "at",
                                Permissions = new Dictionary<string, string>()
                                {
                                    { "test-perm2", "test-perm2-val" },
                                },
                                ExtendedAttributes = "ea",
                                Size = 200,
                                Owner = "owner",
                                Group = "grp",
                                Hidden = false,
                                IsFile = true,
                            }
                        },
                    },
                    Upload = new UploadMessage()
                    {
                        ChunkNumber = 1,
                        ChunkSize = 2,
                        FileID = "fid",
                        FullPath = "fp",
                        TaskID = "tid"
                    },
                    MessageID = "mid",
                    Credentials = new Credential[1]
                    {
                        new Credential()
                        {
                            CredentialType = CredentialType.Plaintext.ToString(),
                            Realm = "realm",
                            CredentialMaterial = "asdf",
                            Account = "tester"
                        }
                    },
                    RemovedFiles = new RemovedFileInformation[1]
                    {
                        new RemovedFileInformation()
                        {
                            Host = "127.0.0.1",
                            Path = "/tmp/path"
                        }
                    },
                    Artifacts = new Artifact[1]
                    {
                        new Artifact()
                        {
                            BaseArtifact = "process",
                            ArtifactDetails = "PID: 123"
                        }
                    }
                }
            };

            SocksDatagram[] dgs = new SocksDatagram[2]
            {
                new SocksDatagram()
                {
                    ServerID = 1,
                    Data = "data1",
                },
                new SocksDatagram()
                {
                    ServerID = 2,
                    Data = "data2"
                }
            };
            TaskingMessage msg = new TaskingMessage()
            {
                Action = MessageAction.GetTasking.ToString(),
                TaskingSize = taskResponses.Length,
                Delegates = new Dictionary<string, string>[2]
                {
                    test,
                    test2,
                },
                Responses = taskResponses,
                Socks = dgs
            };

            string jsonMsg = marshaller.Serialize(msg);
            TaskingMessage tmp = marshaller.Deserialize<TaskingMessage>(jsonMsg);
            Assert.AreEqual(msg.Action, tmp.Action);
            Assert.AreEqual(msg.TaskingSize, tmp.TaskingSize);
            Assert.AreEqual(msg.Delegates.Length, tmp.Delegates.Length);
            Assert.AreEqual(msg.Responses.Length, tmp.Responses.Length);
            Assert.AreEqual(msg.Socks.Length, tmp.Socks.Length);
        }
    }

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
            UploadMessage msg = new UploadMessage()
            {
                ChunkNumber = 0,
                ChunkSize = 1,
                FileID = "test",
                FullPath = "testpath",
                TaskID = "taskid",
            };
            string jsonMsg = marshaller.Serialize(msg);

            UploadMessage tmp = marshaller.Deserialize<UploadMessage>(jsonMsg);

            Assert.AreEqual(msg, tmp);
        }

        [TestMethod]
        public void TestCheckinMessage()
        {
            CheckinMessage msg = new CheckinMessage()
            {
                Action = "checkin",
                OS = "Windows",
                User = "tester",
                Host = "test_host",
                PID = 10,
                IP = "127.0.0.1",
                UUID = UUID,
                Architecture = "x64",
                Domain = "TESTDOMAIN",
                IntegrityLevel = IntegrityLevel.HighIntegrity,
                ExternalIP = "99.99.99.99",
                EncryptionKey = "TEST_ENC_KEY",
                DecryptionKey = "TEST_DEC_KEY",
                PublicKey = "TEST_PUB_KEY",
                SessionID = "TESTSESSION"
            };

            string actualCheckin = marshaller.Serialize(msg);

            CheckinMessage tmp = marshaller.Deserialize<CheckinMessage>(actualCheckin);
            Assert.AreEqual(msg, tmp);
        }

        [TestMethod]
        public void TestEdgeNodeMessage()
        {
            var node = new EdgeNode()
            {
                Source = "test-source",
                Destination = "test-dest",
                Direction = EdgeDirection.SourceToDestination,
                MetaData = "test-meta",
                Action = "test-action",
                C2Profile = "test-c2profile"
            };
            string jsonMsg = marshaller.Serialize(node);
            Assert.AreEqual(node, marshaller.Deserialize<EdgeNode>(jsonMsg));
        }

        [TestMethod]
        public void TestFileBrowserMessage()
        {
            var fb = new FileBrowser()
            {
                Host = "127.0.0.1",
                IsFile = true,
                Permissions = new Dictionary<string, string>() { { "test-perm", "test-perm-val" } },
                Name = "test-name",
                ParentPath = "parent-path",
                Success = true,
                AccessTime = "accesstime",
                ModifyTime = "mod",
                Size = 100,
                Files = new FileInformation[1]
                {
                    new FileInformation()
                    {
                        FullName = "fullname",
                        Name = "name",
                        Directory = "dir",
                        CreationDate = "cd",
                        ModifyTime = "mt",
                        AccessTime = "at",
                        Permissions = new Dictionary<string, string>()
                        {
                            { "test-perm2", "test-perm2-val" },
                        },
                        ExtendedAttributes = "ea",
                        Size = 200,
                        Owner = "owner",
                        Group = "grp",
                        Hidden = false,
                        IsFile = true,
                    }
                },
            };

            string jsonmsg = marshaller.Serialize(fb);
            var res = marshaller.Deserialize<FileBrowser>(jsonmsg);
            Assert.AreEqual(fb.Host, res.Host);
            Assert.AreEqual(fb.IsFile, res.IsFile);
            Assert.AreEqual(fb.Permissions["test-perm"], res.Permissions["test-perm"]);
            Assert.AreEqual(fb.Name, res.Name);
            Assert.AreEqual(fb.ParentPath, res.ParentPath);
            Assert.AreEqual(fb.Success, res.Success);
            Assert.AreEqual(fb.AccessTime, res.AccessTime);
            Assert.AreEqual(fb.ModifyTime, res.ModifyTime);
            Assert.AreEqual(fb.Size, res.Size);
            Assert.AreEqual(fb.Files[0].Permissions["test-perm2"], res.Files[0].Permissions["test-perm2"]);
            Assert.AreEqual(fb.Files[0].FullName, res.Files[0].FullName);
            Assert.AreEqual(fb.Files[0].Name, res.Files[0].Name);
            Assert.AreEqual(fb.Files[0].Directory, res.Files[0].Directory);
            Assert.AreEqual(fb.Files[0].CreationDate, res.Files[0].CreationDate);
            Assert.AreEqual(fb.Files[0].ModifyTime, res.Files[0].ModifyTime);
            Assert.AreEqual(fb.Files[0].AccessTime, res.Files[0].AccessTime);
            Assert.AreEqual(fb.Files[0].ExtendedAttributes, res.Files[0].ExtendedAttributes);
            Assert.AreEqual(fb.Files[0].Size, res.Files[0].Size);
            Assert.AreEqual(fb.Files[0].Owner, res.Files[0].Owner);
            Assert.AreEqual(fb.Files[0].Group, res.Files[0].Group);
            Assert.AreEqual(fb.Files[0].Hidden, res.Files[0].Hidden);
            Assert.AreEqual(fb.Files[0].IsFile, res.Files[0].IsFile);
        }

        [TestMethod]
        public void TestTaskingMessage()
        {
            Dictionary<string, string> test = new Dictionary<string, string>()
            {
                { "delegate1_key", "delegate1_val" }
            };
            Dictionary<string, string> test2 = new Dictionary<string, string>()
            {
                { "delegat2_key", "delegate2_val" }
            };
            TaskResponse[] taskResponses = new TaskResponse[1]
            {
                new TaskResponse()
                {
                    UserOutput = "out1",
                    Completed = true,
                    User = "testuser",
                    WindowTitle = "newtitle",
                    Keystrokes = "asdf",
                    TaskID = "test-id",
                    Status = StatusMessage.Complete.ToString(),
                    Edges = new EdgeNode[1]
                    {
                        new EdgeNode()
                        {
                            Source = "test-source",
                            Destination = "test-dest",
                            Direction = EdgeDirection.SourceToDestination,
                            MetaData = "test-meta",
                            Action = "test-action",
                            C2Profile = "test-c2profile"
                        }
                    },
                    FileBrowser = new FileBrowser()
                    {
                        Host = "127.0.0.1",
                        IsFile = true,
                        Permissions = new Dictionary<string, string>() { { "test-perm", "test-perm-val" } },
                        Name = "test-name",
                        ParentPath = "parent-path",
                        Success = true,
                        AccessTime = "accesstime",
                        ModifyTime = "mod",
                        Size = 100,
                        Files = new FileInformation[1]
                        {
                            new FileInformation()
                            {
                                FullName = "fullname",
                                Name = "name",
                                Directory = "dir",
                                CreationDate = "cd",
                                ModifyTime = "mt",
                                AccessTime = "at",
                                Permissions = new Dictionary<string, string>()
                                {
                                    { "test-perm2", "test-perm2-val" },
                                },
                                ExtendedAttributes = "ea",
                                Size = 200,
                                Owner = "owner",
                                Group = "grp",
                                Hidden = false,
                                IsFile = true,
                            }
                        },
                    },
                    Upload = new UploadMessage()
                    {
                        ChunkNumber = 1,
                        ChunkSize = 2,
                        FileID = "fid",
                        FullPath = "fp",
                        TaskID = "tid"
                    },
                    MessageID = "mid",
                    Credentials = new Credential[1]
                    {
                        new Credential()
                        {
                            CredentialType = CredentialType.Plaintext.ToString(),
                            Realm = "realm",
                            CredentialMaterial = "asdf",
                            Account = "tester"
                        }
                    },
                    RemovedFiles = new RemovedFileInformation[1]
                    {
                        new RemovedFileInformation()
                        {
                            Host = "127.0.0.1",
                            Path = "/tmp/path"
                        }
                    },
                    Artifacts = new Artifact[1]
                    {
                        new Artifact()
                        {
                            BaseArtifact = "process",
                            ArtifactDetails = "PID: 123"
                        }
                    }
                }
            };

            SocksDatagram[] dgs = new SocksDatagram[2]
            {
                new SocksDatagram()
                {
                    ServerID = 1,
                    Data = "data1",
                },
                new SocksDatagram()
                {
                    ServerID = 2,
                    Data = "data2"
                }
            };
            TaskingMessage msg = new TaskingMessage()
            {
                Action = MessageAction.GetTasking.ToString(),
                TaskingSize = taskResponses.Length,
                Delegates = new Dictionary<string, string>[2]
                {
                    test,
                    test2,
                },
                Responses = taskResponses,
                Socks = dgs
            };

            string jsonMsg = marshaller.Serialize(msg);
            TaskingMessage tmp = marshaller.Deserialize<TaskingMessage>(jsonMsg);
            Assert.AreEqual(msg.Action, tmp.Action);
            Assert.AreEqual(msg.TaskingSize, tmp.TaskingSize);
            Assert.AreEqual(msg.Delegates.Length, tmp.Delegates.Length);
            Assert.AreEqual(msg.Responses.Length, tmp.Responses.Length);
            Assert.AreEqual(msg.Socks.Length, tmp.Socks.Length);
        }
    }
}
