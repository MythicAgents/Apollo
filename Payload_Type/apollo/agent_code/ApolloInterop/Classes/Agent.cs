using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;

namespace ApolloInterop.Classes
{
    public abstract class Agent : IAgent
    {
        public int SleepInterval { get; protected set; } = 5;
        public double Jitter { get; protected set; } = 0;
        public bool Alive { get; protected set; } = true;

        protected Random random = new Random((int)DateTime.UtcNow.Ticks);

        public IPeerManager PeerManager { get; protected set; }
        public ITaskManager TaskManager { get; protected set; }
        public ISocksManager SocksManager { get; protected set; }
        public IApi Api { get; protected set; }
        public IC2ProfileManager C2ProfileManager { get; protected set; }
        public ICryptographySerializer Serializer { get; protected set; }
        public string UUID { get; protected set; }

        public Agent(string uuid)
        {
            UUID = uuid;
        }

        public abstract void Start();
        public virtual void Exit() { Alive = false; }
        public virtual void SetSleep(int seconds, double jitter=0)
        {
            SleepInterval = seconds;
            Jitter = jitter;
            if (Jitter != 0)
            {
                Jitter = Jitter / 100.0; 
            }
        }

        public virtual IApi GetApi()
        {
            return Api;
        }
        public virtual int GetSleep()
        {
            if (Jitter == 0 || SleepInterval == 0)
                return SleepInterval;
            int minSleep = (int)(SleepInterval * Jitter);
            int maxSleep = (int)(SleepInterval * (Jitter + 1));
            return (int)(random.NextDouble() * (maxSleep - minSleep) + minSleep);
        }

        public abstract bool GetFileFromMythic(TaskResponse msg, OnResponse<byte[]> onResponse);

        public abstract bool PutFileToMythic(string taskId, byte[] file, OnResponse<string> onResp);

        public virtual bool IsAlive() { return Alive; }

        public virtual ITaskManager GetTaskManager() { return TaskManager; }
        public virtual IPeerManager GetPeerManager() { return PeerManager; }
        public virtual ISocksManager GetSocksManager() { return SocksManager; }
        public virtual IC2ProfileManager GetC2ProfileManager() { return C2ProfileManager; }
        public virtual ICryptographySerializer GetCryptographySerializer() { return Serializer; }

    }
}
