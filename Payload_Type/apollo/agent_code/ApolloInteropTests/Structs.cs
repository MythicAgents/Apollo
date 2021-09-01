using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ApolloInterop.Structs.MythicStructs;

namespace ApolloInteropTests
{
    internal class Structs
    {
        internal static string UUID = "1432d007-b468-4ead-a4ed-2e97ac6fa304";

        internal static UploadMessage Upload = new UploadMessage()
        {
            ChunkNumber = 0,
            ChunkSize = 1,
            FileID = "test",
            FullPath = "testpath",
            TaskID = "taskid",
        };

        internal static CheckinMessage Checkin = new CheckinMessage()
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

        internal static EdgeNode Node = new EdgeNode()
        {
            Source = "test-source",
            Destination = "test-dest",
            Direction = EdgeDirection.SourceToDestination,
            MetaData = "test-meta",
            Action = "test-action",
            C2Profile = "test-c2profile"
        };

        internal static FileInformation File = new FileInformation()
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
        };

        internal static FileInformation File2 = new FileInformation()
        {
            FullName = "fullname2",
            Name = "name2",
            Directory = "dir2",
            CreationDate = "cd2",
            ModifyTime = "mt2",
            AccessTime = "at2",
            Permissions = new Dictionary<string, string>()
                        {
                            { "test-perm3", "test-perm3-val" },
                        },
            ExtendedAttributes = "ea2",
            Size = 150,
            Owner = "owner2",
            Group = "grp2",
            Hidden = true,
            IsFile = false,
        };

        internal static FileInformation[] FileArray = new FileInformation[2]
        {
            File,
            File2
        };

        internal static FileBrowser Browser = new FileBrowser()
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
            Files = FileArray
        };

        internal static RemovedFileInformation Removed = new RemovedFileInformation()
        {
            Host = "127.0.0.1",
            Path = "/tmp/path"
        };

        internal static Credential Cred = new Credential()
        {
            CredentialType = CredentialType.Plaintext.ToString(),
            Realm = "realm",
            CredentialMaterial = "asdf",
            Account = "tester"
        };

        internal static Artifact ArtifactEx = new Artifact()
        {
            BaseArtifact = "process",
            ArtifactDetails = "PID: 123"
        };

        internal static ApolloInterop.Structs.MythicStructs.Task Task1 = new ApolloInterop.Structs.MythicStructs.Task()
        {
            Command = "ls",
            Parameters = "C:\\Users\\Public",
            Timestamp = 10234.56f,
            ID = "some-random-guid"
        };

        internal static ApolloInterop.Structs.MythicStructs.Task Task2 = new ApolloInterop.Structs.MythicStructs.Task()
        {
            Command = "pwd",
            Parameters = "",
            Timestamp = 3333.44f,
            ID = "some-random-guid2"
        };

        internal static MessageResponse Message = new MessageResponse()
        {
            Action = MessageAction.CheckIn.ToString(),
            ID = "test-id",
            Status = StatusMessage.Success.ToString(),

        }

        internal static TaskResponse Response = new TaskResponse()
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
                Node
            },
            FileBrowser = Browser,
            Upload = Upload,
            MessageID = "mid",
            Credentials = new Credential[1]
            {
                Cred
            },
            RemovedFiles = new RemovedFileInformation[1]
            {
                Removed,
            },
            Artifacts = new Artifact[1]
            {
                ArtifactEx
            }
        };

        internal static TaskResponse Response2 = new TaskResponse()
        {
            UserOutput = "out2",
            Completed = true,
            User = "testuser2",
            WindowTitle = "newtitle2",
            Keystrokes = "asdf2",
            TaskID = "test-id2",
            Status = StatusMessage.Complete.ToString(),
            Edges = new EdgeNode[1]
            {
                Node
            },
            FileBrowser = Browser,
            Upload = Upload,
            MessageID = "mid2",
            Credentials = new Credential[1]
            {
                Cred
            },
            RemovedFiles = new RemovedFileInformation[1]
            {
                Removed,
            },
            Artifacts = new Artifact[1]
            {
                ArtifactEx
            }
        };

        internal static SocksDatagram Datagram1 = new SocksDatagram()
        {
            ServerID = 1,
            Data = "data1",
        };

        internal static SocksDatagram Datagram2 = new SocksDatagram()
        {
            ServerID = 2,
            Data = "data2",
        };

        internal static Dictionary<string, string> Delegate1 = new Dictionary<string, string>()
        {
            { "delegate1_key", "delegate1_val" }
        };
        internal static Dictionary<string, string> Delegate2 = new Dictionary<string, string>()
        {
            { "delegat2_key", "delegate2_val" }
        };

        internal static Dictionary<string, string>[] Delegates = new Dictionary<string, string>[2]
        {
            Delegate1,
            Delegate2
        };

        internal static TaskingMessage Tasking = new TaskingMessage()
        {
            Action = MessageAction.GetTasking.ToString(),
            TaskingSize = 2,
            Delegates = Delegates,
            Responses = new TaskResponse[2]
            {
                Response,
                Response2
            },
            Socks = new SocksDatagram[2]
            {
                Datagram1,
                Datagram2
            }
        };
    }
}
