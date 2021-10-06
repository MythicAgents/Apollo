using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Net.Sockets;
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
    public struct IPCChunkedData : IChunkMessage
    {
        [DataMember(Name = "message_type")]
        public MessageType Message;
        [DataMember(Name = "chunk_number")]
        public int ChunkNumber;
        [DataMember(Name = "total_chunks")]
        public int TotalChunks;
        [DataMember(Name = "id")]
        public string ID;
        [DataMember(Name = "data")]
        public string Data;

        public IPCChunkedData(string id="", MessageType mt = 0, int chunkNum = 0, int totalChunks = 1, byte[] data = null)
        {
            if (string.IsNullOrEmpty(id))
            {
                ID = Guid.NewGuid().ToString();
            }
            else
            {
                ID = id;
            }
            Message = mt;
            ChunkNumber = chunkNum;
            TotalChunks = totalChunks;
            Data = Convert.ToBase64String(data);
        }

        public int GetChunkNumber()
        {
            return this.ChunkNumber;
        }

        public int GetChunkSize()
        {
            return this.Data.Length;
        }

        public int GetTotalChunks()
        {
            return this.TotalChunks;
        }
    }

    public struct IPCData
    {
        public TcpClient Client;
        public PipeStream Pipe;
        public Object State;
        public Byte[] Data;
        public int DataLength;
    }
}
