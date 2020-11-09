using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.IO.Pipes;
using Apollo.MessageInbox;

namespace IPC
{
    public class SMBMessageHandler
    {
        private BinaryFormatter bf;
        private Stream PipeStream;
        private Mutex writeMutex = new Mutex();
        private Mutex readMutex = new Mutex();
        private int ChunkSize;
        private Apfell.Crypto.Crypto cryptor;
        public SMBMessageHandler(Stream s, Apfell.Crypto.Crypto _cryptor, int chunkSize = 16384)
        {
            PipeStream = s;
            if (PipeStream.GetType() != typeof(NamedPipeClientStream) && PipeStream.GetType() != typeof(NamedPipeServerStream))
                throw new Exception("SMBMessageHandler stream must be a NamedPipeClientStream or NamedPipeServerStream");
            bf = new BinaryFormatter();
            bf.Binder = new SMBMessageBinder();
            ChunkSize = chunkSize;
            cryptor = _cryptor;
        }


        internal SMBMessage ReadMessage()
        {
            SMBMessage msg = new SMBMessage();
            try
            {
                readMutex.WaitOne();
                msg = (SMBMessage)bf.Deserialize(PipeStream);
                if (msg.MessageType == "new_chunked_message")
                {
                    string info = cryptor.Decrypt(Encoding.UTF8.GetString((byte[])msg.MessageObject));
                    string[] infoParts = info.Split('_');
                    if (infoParts.Length != 2)
                        throw new Exception("Invalid format of new_chunked_message");
                    string guid = infoParts[0];
                    string lengthStr = infoParts[1];
                    int length = 0;
                    if (!int.TryParse(lengthStr, out length))
                        throw new Exception(String.Format("Failed to convert {0} to int", lengthStr));
                    byte[][] smbMessages = new byte[length][];
                    int finalArrayLength = 0;
                    for(int i = 0; i < length; i++)
                    {
                        msg = (SMBMessage)bf.Deserialize(PipeStream);
                        infoParts = msg.MessageType.Split('_');
                        if (infoParts.Length != 3)
                            throw new Exception("Received out of sequence message.");
                        if (infoParts[1] != guid)
                            throw new Exception("Received out of sequence message due to GUID mismatch.");
                        int index = 0;
                        if (!int.TryParse(infoParts[2], out index))
                        {
                            throw new Exception(String.Format("Invalid index given for chunked message: {0}", infoParts[2]));
                        }
                        smbMessages[index] = (byte[])msg.MessageObject;
                        finalArrayLength += ((byte[])msg.MessageObject).Length;
                    }
                    byte[] finalArray = new byte[finalArrayLength];
                    int lastIndex = 0;
                    for(int i = 0; i < smbMessages.Length; i++)
                    {
                        System.Array.Copy(smbMessages[i], 0, finalArray, lastIndex, smbMessages[i].Length);
                        lastIndex += smbMessages[i].Length;
                    }
                    msg.MessageObject = finalArray;
                    msg.MessageType = "";
                }
            }
            finally
            {
                readMutex.ReleaseMutex();
            }
            return msg;
        }

        // Chunked send
        internal bool Send(string id, string message)
        {
            SMBMessage[] messagesToSend;
            string chunkGuidString;
            int i = 0;
            int curIndex = 0;
            chunkGuidString = Guid.NewGuid().ToString();
            List<SMBMessage> smbMsgs = new List<SMBMessage>();
            do
            {
                i++;
                string part;
                if (curIndex + ChunkSize >= message.Length)
                {
                    part = message.Substring(curIndex, message.Length - curIndex);
                }
                else
                {
                    part = message.Substring(curIndex, ChunkSize);
                }
                curIndex += ChunkSize;
                smbMsgs.Add(new SMBMessage()
                {
                    MessageType = string.Format("chunk_{0}_{1}", chunkGuidString, i),
                    MessageObject = Encoding.UTF8.GetBytes(cryptor.Encrypt(part))
                });
            } while (curIndex < message.Length);
            messagesToSend = smbMsgs.ToArray();
            try
            {
                writeMutex.WaitOne();
                if (messagesToSend.Length > 1)
                {
                    string chunkRegistrationMessage = String.Format("{0}_{1}", chunkGuidString, messagesToSend.Length);
                    string chunkTitle = "new_chunked_message";
                    SMBMessage msg = new SMBMessage()
                    {
                        MessageObject = Encoding.UTF8.GetBytes(cryptor.Encrypt(chunkRegistrationMessage)),
                        MessageType = chunkTitle
                    };
                    bf.Serialize(PipeStream, msg);
                }
                for(int j = 0; j < messagesToSend.Length; j++)
                {
                    bf.Serialize(PipeStream, messagesToSend[j]);
                }
            }
            finally
            {
                writeMutex.ReleaseMutex();
            }
            return true;
        }
    }
}
