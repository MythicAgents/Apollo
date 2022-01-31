#define COMMAND_NAME_UPPER

#if DEBUG
#define SPAWNTO_X86
#endif

#if SPAWNTO_X86

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class spawnto_x86 : Tasking
    {
        [DataContract]
        internal struct SpawnToArgsx86
        {
            [DataMember(Name = "application")]
            public string Application;

            [DataMember(Name = "arguments")]
            public string Arguments;
        }


        public spawnto_x86(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
        }



        public override void Start()
        {
            TaskResponse resp;
            SpawnToArgsx86 parameters = _jsonSerializer.Deserialize<SpawnToArgsx86>(_data.Parameters);
            if (_agent.GetProcessManager().SetSpawnTo(parameters.Application, parameters.Arguments, false))
            {
                var sacParams = _agent.GetProcessManager().GetStartupInfo();
                resp = CreateTaskResponse(
                    $"x86 Startup Information set to: {sacParams.Application} {sacParams.Arguments}",
                    true);
            }
            else
            {
                resp = CreateTaskResponse("Failed to set startup information.", true, "error");
            }

            // Your code here..
            // Then add response to queue
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif