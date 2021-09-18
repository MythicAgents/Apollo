using ApolloInterop.Interfaces;
using ApolloInterop.Serializers;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes
{
    public abstract class Peer : IPeer
    {
        protected IAgent _agent;
        protected ISerializer _serializer;
        protected C2ProfileData _c2ProfileData;
        protected string _uuid;
        protected string _mythicUUID;
        protected bool _previouslyConnected;

        public Peer(IAgent agent, C2ProfileData data, ISerializer serializer = null)
        {
            _agent = agent;
            _c2ProfileData = data;
            _uuid = agent.GetApi().NewUUID();
            _previouslyConnected = false;
            if (serializer == null)
            {
                _serializer = new JsonSerializer();
            }
        }

        public abstract bool Start();
        public abstract void Stop();
        public abstract bool Connected();
        public abstract void ProcessMessage(DelegateMessage message);
        public virtual string GetUUID() { return _uuid; }
        public virtual string GetMythicUUID() { return _mythicUUID; }
        public abstract bool Finished();



    }
}
