using System;
using System.Runtime.Serialization;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using sCredentialType = System.String;
using sStatusMessage = System.String;
using sMessageAction = System.String;
using ApolloInterop.Interfaces;
using ApolloInterop.Enums.ApolloEnums;

namespace ApolloInterop.Structs
{

    namespace MythicStructs
    {
        [DataContract]
        public struct PeerInformation
        {
            [DataMember(Name = "host")]
            public string Hostname;
            [DataMember(Name = "c2_profile")]
            public C2ProfileData C2Profile;
            [DataMember(Name = "agent_uuid")]
            public string AgentUUID;
        }

        // Profile data sent from the Mythic Server
        [DataContract]
        public struct C2ProfileData : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.C2ProfileData;
            }
            [DataMember(Name = "name")]
            public string Name;
            [DataMember(Name = "is_p2p")]
            public bool IsP2P;
            [DataMember(Name = "parameters")]
            public C2ProfileInstanceParameters Parameters;
        }

        [DataContract]
        public struct C2ProfileInstanceParameters
        {
            [DataMember(Name = "encrypted_exchange_check")]
            public string EncryptedExchangeCheck;
            [DataMember(Name = "pipename")]
            public string PipeName;
            [DataMember(Name = "AESPSK")]
            public string AESPSK;
            [DataMember(Name = "killdate")]
            public string KillDate;
        }

        public class CredentialType
        {
            private CredentialType(string value) { Value = value; }
            public string Value { get; private set; }
            public override string ToString() { return Value; }
            public static CredentialType Plaintext { get { return new CredentialType("plaintext"); } }
            public static CredentialType Certificate { get { return new CredentialType("certificate"); } }
            public static CredentialType Hash { get { return new CredentialType("hash"); } }
            public static CredentialType Key { get { return new CredentialType("key"); } }
            public static CredentialType Ticket { get { return new CredentialType("ticket"); } }
            public static CredentialType Cookie { get { return new CredentialType("cookie"); } }

            public static bool operator ==(CredentialType a, CredentialType b) { return a.Value == b.Value; }

            public static bool operator !=(CredentialType a, CredentialType b) { return a.Value != b.Value; }

            public static bool operator ==(string a, CredentialType b) { return a == b.Value; }

            public static bool operator !=(string a, CredentialType b) { return a == b.Value; }
        }

        [DataContract]
        public struct Credential : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.Credential;
            }
            [DataMember(Name = "credential_type")]
            public string CredentialType;
            [DataMember(Name = "realm")]
            public string Realm;
            [DataMember(Name = "credential")]
            public string CredentialMaterial;
            [DataMember(Name = "account")]
            public string Account;
        }

        [DataContract]
        public struct RemovedFileInformation : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.RemovedFileInformation;
            }
            [DataMember(Name = "host")]
            public string Host;
            [DataMember(Name = "path")]
            public string Path;
        }

        [DataContract]
        public struct FileInformation : IEquatable<FileInformation>, IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.FileInformation;
            }
            [DataMember(Name = "full_name")]
            public string FullName;
            [DataMember(Name = "name")]
            public string Name;
            [DataMember(Name = "directory")]
            public string Directory;
            [DataMember(Name = "creation_date")]
            public string CreationDate;
            [DataMember(Name = "modify_time")]
            public string ModifyTime;
            [DataMember(Name = "access_time")]
            public string AccessTime;
            [DataMember(Name = "permissions")]
            public Dictionary<string, string> Permissions;
            [DataMember(Name = "extended_attributes")]
            public string ExtendedAttributes;
            [DataMember(Name = "size")]
            public int Size;
            [DataMember(Name = "owner")]
            public string Owner;
            [DataMember(Name = "group")]
            public string Group;
            [DataMember(Name = "hidden")]
            public bool Hidden;
            [DataMember(Name = "is_file")]
            public bool IsFile;

            public override bool Equals(object obj)
            {
                return obj is FileInformation && this.Equals(obj);
            }

            public bool Equals(FileInformation obj)
            {
                if (this.Permissions.Keys.Count != obj.Permissions.Keys.Count)
                    return false;
                foreach (string k in this.Permissions.Keys)
                {
                    if (this.Permissions[k] != obj.Permissions[k])
                        return false;
                }
                return this.FullName == obj.FullName &&
                    this.Name == obj.Name &&
                    this.Directory == obj.Directory &&
                    this.CreationDate == obj.CreationDate &&
                    this.ModifyTime == obj.ModifyTime &&
                    this.AccessTime == obj.AccessTime &&
                    this.ExtendedAttributes == obj.ExtendedAttributes &&
                    this.Size == obj.Size &&
                    this.Owner == obj.Owner &&
                    this.Group == obj.Group &&
                    this.Hidden == obj.Hidden &&
                    this.IsFile == obj.IsFile;
            }
        }

        [DataContract]
        public struct FileBrowser : IEquatable<FileBrowser>, IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.FileBrowser;
            }
            [DataMember(Name = "host")]
            public string Host;
            [DataMember(Name = "is_file")]
            public bool IsFile;
            [DataMember(Name = "permissions")]
            public Dictionary<string, string> Permissions;
            [DataMember(Name = "name")]
            public string Name;
            [DataMember(Name = "parent_path")]
            public string ParentPath;
            [DataMember(Name = "success")]
            public bool Success;
            [DataMember(Name = "access_time")]
            public string AccessTime;
            [DataMember(Name = "modify_time")]
            public string ModifyTime;
            [DataMember(Name = "size")]
            public int Size;
            [DataMember(Name = "files")]
            public FileInformation[] Files;

            public override bool Equals(object obj)
            {
                return obj is FileBrowser && Equals((FileBrowser)obj);
            }

            public bool Equals(FileBrowser obj)
            {
                for (int i = 0; i < this.Files.Length; i++)
                {
                    if (!this.Files[i].Equals(obj.Files[i]))
                    {
                        return false;
                    }
                }
                foreach (string key in this.Permissions.Keys)
                {
                    if (this.Permissions[key] != obj.Permissions[key])
                        return false;
                }
                return this.Host == obj.Host &&
                    this.IsFile == obj.IsFile &&
                    this.Name == obj.Name &&
                    this.ParentPath == obj.ParentPath &&
                    this.Success == obj.Success &&
                    this.AccessTime == obj.AccessTime &&
                    this.ModifyTime == obj.ModifyTime &&
                    this.Size == obj.Size;
            }
        }
        public enum EdgeDirection
        {
            SourceToDestination = 1,
            DestinationToSource,
            BiDirectional
        }

        [DataContract]
        public struct EdgeNode : IEquatable<EdgeNode>, IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.EdgeNode;
            }
            [DataMember(Name = "source")]
            public string Source;
            [DataMember(Name = "destination")]
            public string Destination;
            [DataMember(Name = "direction")]
            public EdgeDirection Direction;
            [DataMember(Name = "metadata")]
            public string MetaData;
            [DataMember(Name = "action")]
            public string Action;
            [DataMember(Name = "c2_profile")]
            public string C2Profile;


            public override bool Equals(object obj)
            {
                return obj is EdgeNode && this.Equals(obj);
            }

            public bool Equals(EdgeNode node)
            {
                return this.Source == node.Source &&
                    this.Destination == node.Destination &&
                    this.Direction == node.Direction &&
                    this.MetaData == node.MetaData &&
                    this.Action == node.Action &&
                    this.C2Profile == node.C2Profile;
            }
        }

        [DataContract]
        public struct SocksDatagram : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.SocksDatagram;
            }
            [DataMember(Name = "server_id")]
            public int ServerID;
            [DataMember(Name = "data")]
            public string Data;
        }

        [DataContract]
        public struct Artifact : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.Artifact;
            }
            [DataMember(Name = "base_artifact")]
            public string BaseArtifact;
            [DataMember(Name = "artifact")]
            public string ArtifactDetails;
        }

        public class StatusMessage
        {
            private StatusMessage(string value) { Value = value; }
            public string Value { get; private set; }
            public override string ToString() { return Value; }
            public static StatusMessage Success { get { return new StatusMessage("success"); } }
            public static StatusMessage Error { get { return new StatusMessage("error"); } }
            public static StatusMessage Processing { get { return new StatusMessage("processing"); } }
            public static StatusMessage Complete { get { return new StatusMessage("complete"); } }

            public static bool operator ==(StatusMessage a, StatusMessage b) { return a.ToString() == b.ToString(); }

            public static bool operator !=(StatusMessage a, StatusMessage b) { return a.ToString() != b.ToString(); }

            public static bool operator ==(string a, StatusMessage b) { return a == b.ToString(); }

            public static bool operator !=(string a, StatusMessage b) { return a == b.ToString(); }
        }

        [DataContract]
        public struct TaskStatus : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.TaskStatus;
            }
            [DataMember(Name = "task_id")]
            public string TaskID;
            [DataMember(Name = "status")]
            public sStatusMessage StatusMessage;
            [DataMember(Name = "error")]
            public string Error;
            [DataMember(Name = "total_chunks")]
            public int TotalChunks;
            [DataMember(Name = "chunk_num")]
            public int ChunkNumber;
            [DataMember(Name = "chunk_data")]
            public string ChunkData;
            [DataMember(Name = "file_id")]
            public string FileID;
        }

        [DataContract]
        public struct TaskResponse : IEquatable<TaskResponse>, IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.TaskResponse;
            }
            [DataMember(Name = "user_output")]
            public object UserOutput;
            [DataMember(Name = "completed")]
            public bool? Completed;
            [DataMember(Name = "user")]
            public string User;
            [DataMember(Name = "window_title")]
            public string WindowTitle;
            [DataMember(Name = "keystrokes")]
            public string Keystrokes;
            [DataMember(Name = "task_id")]
            public string TaskID;
            [DataMember(Name = "status")]
            public sStatusMessage Status;
            [DataMember(Name = "edges")]
            public EdgeNode[] Edges;
            [DataMember(Name = "file_browser")]
            public FileBrowser? FileBrowser;
            [DataMember(Name = "upload")]
            public UploadMessage Upload;
            [DataMember(Name = "message_id")]
            public string MessageID;
            [DataMember(Name = "credentials")]
            public Credential[] Credentials;
            [DataMember(Name = "removed_files")]
            public RemovedFileInformation[] RemovedFiles;
            [DataMember(Name = "artifacts")]
            public Artifact[] Artifacts;

            public override bool Equals(object obj)
            {
                return obj is TaskingMessage && this.Equals((TaskResponse)obj);
            }

            public bool Equals(TaskResponse msg)
            {
                for (int i = 0; i < this.Edges.Length; i++)
                {
                    if (!this.Edges[i].Equals(msg.Edges[i]))
                        return false;
                }
                for (int i = 0; i < this.Credentials.Length; i++)
                {
                    if (!this.Credentials[i].Equals(msg.Credentials[i]))
                        return false;
                }
                for (int i = 0; i < this.RemovedFiles.Length; i++)
                {
                    if (!this.RemovedFiles[i].Equals(msg.RemovedFiles[i]))
                        return false;
                }
                for (int i = 0; i < this.Artifacts.Length; i++)
                {
                    if (!this.Artifacts[i].Equals(msg.Artifacts[i]))
                        return false;
                }
                return this.FileBrowser.Equals(msg.FileBrowser) &&
                    this.UserOutput.Equals(msg.UserOutput) &&
                    this.Completed == msg.Completed &&
                    this.User == msg.User &&
                    this.WindowTitle == msg.WindowTitle &&
                    this.TaskID == msg.TaskID &&
                    this.Keystrokes == msg.Keystrokes &&
                    this.Status == msg.Status &&
                    this.Upload.Equals(msg.Upload) &&
                    this.MessageID == msg.MessageID;

            }
        }

        [DataContract]
        public struct DownloadRegistrationMessage : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.DownloadRegistrationMessage;
            }
            [DataMember(Name = "task_id")]
            public string TaskID;
            [DataMember(Name = "total_chunks")]
            public int TotalChunks;
            [DataMember(Name = "full_path")]
            public string FullPath;
            [DataMember(Name = "host")]
            public string Host;
            [DataMember(Name = "is_screenshot")]
            public bool IsScreenshot;
        }

        [DataContract]
        public struct DownloadProgressMessage : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.DownloadProgressMessage;
            }
            [DataMember(Name = "task_id")]
            public string TaskID;
            [DataMember(Name = "file_id")]
            public string FileID;
            [DataMember(Name = "chunk_num")]
            public int ChunkNumber;
            [DataMember(Name = "chunk_data")]
            public string ChunkData;
        }

        [DataContract]
        public struct Task : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.Task;
            }
            [DataMember(Name = "command")]
            public string Command;
            [DataMember(Name = "parameters")]
            public string Parameters;
            [DataMember(Name = "timestamp")]
            public float Timestamp;
            [DataMember(Name = "id")]
            public string ID;
        }

        public class MessageAction
        {
            private MessageAction(string value) { Value = value; }
            public string Value { get; private set; }
            public override string ToString() { return Value; }
            public static MessageAction GetTasking { get { return new MessageAction("get_tasking"); } }
            public static MessageAction PostResponse { get { return new MessageAction("post_response"); } }
            public static MessageAction CheckIn { get { return new MessageAction("checkin"); } }
            public static MessageAction Upload { get { return new MessageAction("upload"); } }
            public static MessageAction StagingRSA { get { return new MessageAction("staging_rsa"); } }
            public static MessageAction StagingDH { get { return new MessageAction("staging_dh"); } }

            public static bool operator ==(MessageAction a, MessageAction b) { return a.ToString() == b.ToString(); }

            public static bool operator !=(MessageAction a, MessageAction b) { return a.ToString() != b.ToString(); }

            public static bool operator ==(string a, MessageAction b) { return a == b.ToString(); }

            public static bool operator !=(string a, MessageAction b) { return a == b.ToString(); }
        }

        public enum IntegrityLevel
        {
            UnknownIntegrity = 0,
            LowIntegrity,
            MediumIntegrity,
            HighIntegrity,
            SystemIntegrity
        }

        [DataContract]
        public struct DelegateMessage : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.DelegateMessage;
            }
            [DataMember(Name = "uuid")]
            public string UUID;
            [DataMember(Name = "mythic_uuid")]
            public string MythicUUID;
            [DataMember(Name = "message")]
            public string Message;
            [DataMember(Name = "c2_profile")]
            public string C2Profile;
        }

        [DataContract]
        public struct TaskingMessage : IEquatable<TaskingMessage>, IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.TaskingMessage;
            }
            [DataMember(Name = "action")]
            public string Action;
            [DataMember(Name = "tasking_size")]
            public int TaskingSize;
            [DataMember(Name = "delegates")]
            public DelegateMessage[] Delegates;
            [DataMember(Name = "responses")]
            public TaskResponse[] Responses;
            [DataMember(Name = "socks")]
            public SocksDatagram[] Socks;

            public override bool Equals(object obj)
            {
                return obj is TaskingMessage && this.Equals(obj);
            }

            public bool Equals(TaskingMessage obj)
            {
                if (this.Delegates.Length != obj.Delegates.Length)
                    return false;
                if (this.Socks.Length != obj.Socks.Length)
                    return false;
                for (int i = 0; i < this.Delegates.Length; i++)
                {
                    var d1 = this.Delegates[i];
                    var d2 = obj.Delegates[i];
                    if (!d1.Equals(d2))
                        return false;
                }
                for (int i = 0; i < this.Socks.Length; i++)
                {
                    if (!this.Socks[i].Equals(obj.Socks[i]))
                    {
                        return false;
                    }
                }
                return this.Action == obj.Action && this.TaskingSize == obj.TaskingSize;
            }
        }

        [DataContract]
        public struct EKEHandshakeMessage : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.EKEHandshakeMessage;
            }
            [DataMember(Name = "action")]
            public string Action;
            [DataMember(Name = "pub_key")]
            public string PublicKey;
            [DataMember(Name = "session_id")]
            public string SessionID;
        }


        /*
         * "action": "staging_rsa",
        "uuid": "UUID", // new UUID for the next message
        "session_key": Base64( RSAPub( new aes session key ) ),
        "session_id": "same 20 char string back"
        })
         */
        [DataContract]
        public struct EKEHandshakeResponse : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.EKEHandshakeResponse;
            }
            [DataMember(Name = "action")]
            public string Action;
            [DataMember(Name = "uuid")]
            public string UUID;
            [DataMember(Name = "session_key")]
            public string SessionKey;
            [DataMember(Name = "session_id")]
            public string SessionID;
        }

        [DataContract]
        public struct CheckinMessage : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.CheckinMessage;
            }
            [DataMember(Name = "action")]
            public string Action;
            [DataMember(Name = "os")]
            public string OS;
            [DataMember(Name = "user")]
            public string User;
            [DataMember(Name = "host")]
            public string Host;
            [DataMember(Name = "pid")]
            public int PID;
            [DataMember(Name = "ip")]
            public string IP;
            [DataMember(Name = "uuid")]
            public string UUID;
            [DataMember(Name = "architecture")]
            public string Architecture;
            [DataMember(Name = "domain")]
            public string Domain;
            [DataMember(Name = "integrity_level")]
            public IntegrityLevel IntegrityLevel;
            [DataMember(Name = "external_ip")]
            public string ExternalIP;
            [DataMember(Name = "encryption_key")]
            public string EncryptionKey;
            [DataMember(Name = "decryption_key")]
            public string DecryptionKey;
            [DataMember(Name = "pub_key")]
            public string PublicKey;
            [DataMember(Name = "session_id")]
            public string SessionID;
        }

        [DataContract]
        public struct UploadMessage : IEquatable<UploadMessage>, IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.UploadMessage;
            }
            [DataMember(Name = "chunk_size")]
            public int ChunkSize;
            [DataMember(Name = "file_id")]
            public string FileID;
            [DataMember(Name = "chunk_num")]
            public int ChunkNumber;
            [DataMember(Name = "full_path")]
            public string FullPath;
            [DataMember(Name = "task_id")]
            public string TaskID;

            public override bool Equals(object obj)
            {
                return obj is UploadMessage && this.Equals((UploadMessage)obj);
            }

            public bool Equals(UploadMessage obj)
            {
                return this.ChunkNumber == obj.ChunkNumber &&
                    this.ChunkSize == obj.ChunkSize &&
                    this.FileID == obj.FileID &&
                    this.FullPath == obj.FullPath &&
                    this.TaskID == obj.TaskID;
            }
        }

        [DataContract]
        public struct MessageResponse : IEquatable<MessageResponse>, IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.MessageResponse;
            }
            [DataMember(Name = "action")]
            public sMessageAction Action;
            [DataMember(Name = "id")]
            public string ID;
            [DataMember(Name = "uuid")]
            public string UUID;
            [DataMember(Name = "status")]
            public sStatusMessage Status;
            [DataMember(Name = "tasks")]
            public Task[] Tasks;
            [DataMember(Name = "responses")]
            public TaskStatus[] Responses;
            [DataMember(Name = "delegates")]
            public DelegateMessage[] Delegates;
            [DataMember(Name = "session_key")]
            public string SessionKey;
            [DataMember(Name = "session_id")]
            public string SessionID;
            [DataMember(Name = "total_chunks")]
            public int TotalChunks;
            [DataMember(Name = "chunk_num")]
            public int ChunkNumber;
            [DataMember(Name = "chunk_data")]
            public string ChunkData;
            [DataMember(Name = "file_id")]
            public string FileID;
            [DataMember(Name = "task_id")]
            public string TaskID;

            public override bool Equals(object obj)
            {
                return obj is MessageResponse && this.Equals((MessageResponse)obj);
            }

            public bool Equals(MessageResponse obj)
            {
                if (this.Tasks.Length != obj.Tasks.Length)
                    return false;
                if (this.Responses.Length != obj.Responses.Length)
                    return false;
                if (this.Delegates.Length != obj.Delegates.Length)
                    return false;

                for (int i = 0; i < this.Tasks.Length; i++)
                {
                    if (!this.Tasks[i].Equals(obj.Tasks[i]))
                        return false;
                }
                for (int i = 0; i < this.Responses.Length; i++)
                {
                    if (!this.Responses[i].Equals(obj.Responses[i]))
                        return false;
                }
                for (int i = 0; i < this.Delegates.Length; i++)
                {
                    if (!this.Delegates[i].Equals(obj.Delegates[i]))
                    {
                        return false;
                    }
                }
                return this.Action == obj.Action &&
                    this.ID == obj.ID &&
                    this.Status == obj.Status &&
                    this.SessionID == obj.SessionID &&
                    this.SessionKey == obj.SessionKey &&
                    this.TotalChunks == obj.TotalChunks &&
                    this.ChunkData == obj.ChunkData &&
                    this.ChunkNumber == obj.ChunkNumber &&
                    this.FileID == obj.FileID &&
                    this.TaskID == obj.TaskID;

            }
        }
    }
}
