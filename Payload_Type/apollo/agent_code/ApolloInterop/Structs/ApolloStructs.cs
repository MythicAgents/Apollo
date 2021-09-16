using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace ApolloInterop.Structs.ApolloStructs
{
    public struct C2ProfileData
    {
        public Type TC2Profile;
        public Type TCryptography;
        public Type TSerializer;
        public Dictionary<string, string> Parameters;
    }

    [DataContract]
    public struct PeerMessage
    {
        [DataMember(Name = "message")]
        public string Message;
        [DataMember(Name = "type")]
        public MessageType Type;
    }

    [DataContract]
    public struct IPCData
    {
        public PipeStream Pipe;
        public Object State;
        [DataMember(Name = "data")]
        public Byte[] Data;
        [DataMember(Name = "data_len")]
        public int DataLength;
        [DataMember(Name = "message_type")]
        public MessageType Message;
        [DataMember(Name = "chunk_number")]
        public int ChunkNumber;
        [DataMember(Name = "total_chunks")]
        public int TotalChunks;
        [DataMember(Name = "id")]
        public string ID;

        public IPCData(byte[] data, MessageType type, int chunkNum=0, int totalChunks=1, PipeStream p = null, Object s = null, string id = null, int dataLen = -1)
        {
            if (id == null)
                ID = Guid.NewGuid().ToString();
            Data = data;
            Message = type;
            ChunkNumber = chunkNum;
            TotalChunks = totalChunks;
            Pipe = p;
            State = s;
            DataLength = dataLen;
            if (string.IsNullOrEmpty(id))
                ID = Guid.NewGuid().ToString();
            else
                ID = id;
        }
    }
}
