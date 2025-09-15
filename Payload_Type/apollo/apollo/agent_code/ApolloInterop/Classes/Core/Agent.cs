﻿using System;
using System.Threading;
using ApolloInterop.Features.KerberosTickets;
using ApolloInterop.Interfaces;

namespace ApolloInterop.Classes
{
    public abstract class Agent : IAgent
    {
        private static Mutex _outputLock = new Mutex();
        public int SleepInterval { get; protected set; } = 0;
        public double Jitter { get; protected set; } = 0;
        protected AutoResetEvent _sleepReset = new AutoResetEvent(false);
        protected AutoResetEvent _exit = new AutoResetEvent(false);
        protected WaitHandle[] _agentSleepHandles;
        public bool Alive { get; protected set; } = true;

        protected Random random = new Random((int)DateTime.UtcNow.Ticks);

        public IPeerManager PeerManager { get; protected set; }
        public ITaskManager TaskManager { get; protected set; }
        public ISocksManager SocksManager { get; protected set; }
        public IRpfwdManager RpfwdManager { get; protected set; }
        public IApi Api { get; protected set; }
        public IC2ProfileManager C2ProfileManager { get; protected set; }
        public ICryptographySerializer Serializer { get; protected set; }
        public IFileManager FileManager { get; protected set; }
        public IIdentityManager IdentityManager { get; protected set; }
        public IProcessManager ProcessManager { get; protected set; }
        public IInjectionManager InjectionManager { get; protected set; }
        
        public ITicketManager TicketManager { get; protected set; }
        public string UUID { get; protected set; }

        public Agent(string uuid)
        {
            UUID = uuid;
            _agentSleepHandles = new WaitHandle[]
            {
                _sleepReset,
                _exit
            };
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
            WaitHandle[] sleepers = _agentSleepHandles;
            if (handles != null)
            {
                WaitHandle[] tmp = new WaitHandle[handles.Length + sleepers.Length];
                Array.Copy(handles, tmp, handles.Length);
                Array.Copy(sleepers, 0, tmp, handles.Length, sleepers.Length);
                sleepers = tmp;
            }
            WaitHandle.WaitAny(sleepers, sleepTime);
        }

        public void AcquireOutputLock()
        {
            _outputLock.WaitOne();
        }

        public void ReleaseOutputLock()
        {
            _outputLock.ReleaseMutex();
        }
        
        public virtual bool IsAlive() { return Alive; }

        public virtual ITaskManager GetTaskManager() { return TaskManager; }
        public virtual IPeerManager GetPeerManager() { return PeerManager; }
        public virtual ISocksManager GetSocksManager() { return SocksManager; }
        public virtual IRpfwdManager GetRpfwdManager() { return RpfwdManager; }
        public virtual IC2ProfileManager GetC2ProfileManager() { return C2ProfileManager; }
        public virtual ICryptographySerializer GetCryptographySerializer() { return Serializer; }
        public virtual IFileManager GetFileManager() { return FileManager; }
        public virtual IIdentityManager GetIdentityManager() { return IdentityManager; }
        public virtual IProcessManager GetProcessManager() { return ProcessManager; }
        public virtual IInjectionManager GetInjectionManager() { return InjectionManager; }
        
        public virtual ITicketManager GetTicketManager() { return TicketManager; }
        public string GetUUID()
        {
            return UUID;
        }
        public void SetUUID(string newUUID){
            UUID = newUUID;
        }

    }
}
