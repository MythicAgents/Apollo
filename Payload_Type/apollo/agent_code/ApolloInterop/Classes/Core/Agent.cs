using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;

namespace ApolloInterop.Classes
{
    public abstract class Agent : IAgent
    {
        public int SleepInterval { get; protected set; } = 0;
        public double Jitter { get; protected set; } = 0;
        protected AutoResetEvent _sleepReset = new AutoResetEvent(false);
        protected AutoResetEvent _exit = new AutoResetEvent(false);
        public bool Alive { get; protected set; } = true;

        protected Random random = new Random((int)DateTime.UtcNow.Ticks);

        public IPeerManager PeerManager { get; protected set; }
        public ITaskManager TaskManager { get; protected set; }
        public ISocksManager SocksManager { get; protected set; }
        public IApi Api { get; protected set; }
        public IC2ProfileManager C2ProfileManager { get; protected set; }
        public ICryptographySerializer Serializer { get; protected set; }
        public IFileManager FileManager { get; protected set; }
        public IIdentityManager IdentityManager { get; protected set; }
        public IProcessManager ProcessManager { get; protected set; }
        public IInjectionManager InjectionManager { get; protected set; }
        public string UUID { get; protected set; }

        public Agent(string uuid)
        {
            UUID = uuid;
        }

        public abstract void Start();
        public virtual void Exit() { Alive = false; _exit.Set(); }
        public virtual void SetSleep(int seconds, double jitter=0)
        {
            SleepInterval = seconds * 1000;
            Jitter = jitter;
            if (Jitter != 0)
            {
                Jitter = Jitter / 100.0; 
            }
            _sleepReset.Set();
        }

        public virtual IApi GetApi()
        {
            return Api;
        }
        public virtual void Sleep(WaitHandle[] handles = null)
        {
            int sleepTime = SleepInterval;
            if (Jitter != 0)
            {
                int minSleep = (int)(SleepInterval * (1 - Jitter));
                int maxSleep = (int)(SleepInterval * (Jitter + 1));
                sleepTime = (int)(random.NextDouble() * (maxSleep - minSleep) + minSleep);
            }
            List<WaitHandle> newHandles = new List<WaitHandle>();
            newHandles.Add(_sleepReset);
            newHandles.Add(_exit);
            if (handles != null)
            {
                foreach(WaitHandle h in handles)
                {
                    newHandles.Add(h);
                }
            }
            WaitHandle.WaitAny(newHandles.ToArray(), sleepTime);
        }

        public abstract bool GetFileFromMythic(TaskResponse msg, OnResponse<byte[]> onResponse);

        public abstract bool PutFileToMythic(string taskId, byte[] file, OnResponse<string> onResp);

        public virtual bool IsAlive() { return Alive; }

        public virtual ITaskManager GetTaskManager() { return TaskManager; }
        public virtual IPeerManager GetPeerManager() { return PeerManager; }
        public virtual ISocksManager GetSocksManager() { return SocksManager; }
        public virtual IC2ProfileManager GetC2ProfileManager() { return C2ProfileManager; }
        public virtual ICryptographySerializer GetCryptographySerializer() { return Serializer; }
        public virtual IFileManager GetFileManager() { return FileManager; }
        public virtual IIdentityManager GetIdentityManager() { return IdentityManager; }
        public virtual IProcessManager GetProcessManager() { return ProcessManager; }
        public virtual IInjectionManager GetInjectionManager() { return InjectionManager; }
        public string GetUUID()
        {
            return UUID;
        }

    }
}
