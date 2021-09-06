using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes
{
    public abstract class Peer : IPeer
    {
        protected IAgent Agent;
        protected IC2Profile Profile;
        protected string UUID;

        public Peer(IAgent agent, IC2Profile profile)
        {
            Agent = agent;
            Profile = profile;
            UUID = agent.GetApi().NewUUID();
        }

        public abstract void Start();
        public abstract void Stop();
        public abstract string Connected();
        public abstract string ProcessMessage(DelegateMessage message);
        public virtual string GetUUID() { return UUID; }
        public abstract bool Finished();



    }
}
