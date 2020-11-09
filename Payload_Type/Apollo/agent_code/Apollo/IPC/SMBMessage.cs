using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.Serialization;

namespace IPC
{
    [Serializable]
    class SMBMessage
    {
        public string MessageID;
        public int MessageNumber;
        public int MaxMessages;
        public string MessageType;
        public object MessageObject;

        internal static int maxMessageSize = 25600;

        internal static byte[] CombineChunkedMessages(List<SMBMessage> messages)
        {
            byte[][] sortedMessages = new byte[messages.Count][];
            byte[] result;
            int totalMessageLength = 0;
            int lastIndex = 0;
            foreach (SMBMessage msg in messages)
            {
                sortedMessages[msg.MessageNumber] = (byte[])msg.MessageObject;
                totalMessageLength += ((byte[])msg.MessageObject).Length;
            }
            result = new byte[totalMessageLength];
            for (int i = 0; i < sortedMessages.Length; i++)
            {
                /*
                 * System.Buffer.BlockCopy(a1, 0, rv, 0, a1.Length);
System.Buffer.BlockCopy(a2, 0, rv, a1.Length, a2.Length);
System.Buffer.BlockCopy(a3, 0, rv, a1.Length + a2.Length, a3.Length);*/
                if (i != 0)
                    lastIndex += sortedMessages[i - 1].Length;
                System.Buffer.BlockCopy(sortedMessages[i], 0, result, lastIndex, sortedMessages[i].Length);
            }
            return result;
        }

        internal static bool RequiresChunking(int messageObjectLength)
        {
            return messageObjectLength > maxMessageSize;
        }

        internal static SMBMessage[] CreateChunkedMessages(byte[] messageObject)
        {
            int numberOfMessages = (messageObject.Length / maxMessageSize) + 1;
            SMBMessage[] results = new SMBMessage[numberOfMessages];
            string id = Guid.NewGuid().ToString();
            for (int i = 0; i < results.Length; i++)
            {
                SMBMessage msg = new SMBMessage()
                {
                    MessageID = id,
                    MaxMessages = numberOfMessages,
                    MessageType = "chunked_message",
                    MessageNumber = i
                };
                byte[] msgData;
                if ((i + 1) == results.Length)
                {
                    int bytesToCopy = messageObject.Length - (maxMessageSize * (results.Length - 1));
                    msgData = new byte[bytesToCopy];
                    System.Buffer.BlockCopy(messageObject, i * maxMessageSize, msgData, 0, bytesToCopy);
                } else
                {
                    msgData = new byte[maxMessageSize];
                    System.Buffer.BlockCopy(messageObject, i * maxMessageSize, msgData, 0, maxMessageSize);
                }
                msg.MessageObject = msgData;
                results[i] = msg;
            }
            return results;
        }

    }

    public class SMBMessageBinder : SerializationBinder
    {
        public override Type BindToType(string assemblyName, string typeName)
        {
            if (typeName == "IPC.SMBMessage")
            {
                return typeof(SMBMessage);
            }
            else if (typeName == "Apollo.Jobs.Job")
            {
                return typeof(Apollo.Jobs.Job);
            }
            else if (typeName == "Apollo.Tasks.Task")
            {
                return typeof(Apollo.Tasks.Task);
            }
            else
            {
                return typeof(Nullable);
            }
        }
    }
}