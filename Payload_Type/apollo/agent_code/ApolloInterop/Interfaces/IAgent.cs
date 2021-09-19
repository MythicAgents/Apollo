using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Types.Delegates;
using ApolloInterop.Structs.MythicStructs;

namespace ApolloInterop.Interfaces
{
    public interface IAgent
    {
        // Start the agent.
        void Start();

        // Kill the agent.
        void Exit();

        // Set agent sleep
        void SetSleep(int seconds, double jitter=0);

        // Fetch sleep
        int GetSleep();

        // Retrieve a file from Mythic server and do something with file contents.
        bool GetFileFromMythic(TaskResponse msg, OnResponse<byte[]> onResponse);

        // Put a file to Mythic with the specified data, and report back the new
        // file UUID on response.
        bool PutFileToMythic(string taskId, byte[] file, OnResponse<string> onResponse);

        bool IsAlive();

        string GetUUID();

        ITaskManager GetTaskManager();
        IPeerManager GetPeerManager();

        ISocksManager GetSocksManager();

        IC2ProfileManager GetC2ProfileManager();

        //ICryptographySerializer GetCryptographySerializer();

        IApi GetApi();
    }
}
