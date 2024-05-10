#define COMMAND_NAME_UPPER

#if DEBUG
#define SPAWNTO_X64
#endif

#if SPAWNTO_X64

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;

namespace Tasks
{
    public class spawnto_x64 : Tasking
    {
        [DataContract]
        internal struct SpawnToArgsx64
        {
            [DataMember(Name = "application")]
            public string Application;

            [DataMember(Name = "arguments")]
            public string Arguments;
        }

        public spawnto_x64(IAgent agent, ApolloInterop.Structs.MythicStructs.MythicTask data) : base(agent, data)
        {
        }


        public override void Start()
        {
            MythicTaskResponse resp;
            SpawnToArgsx64 parameters = _jsonSerializer.Deserialize<SpawnToArgsx64>(_data.Parameters);
            if (_agent.GetProcessManager().SetSpawnTo(parameters.Application, parameters.Arguments, true))
            {
                var sacParams = _agent.GetProcessManager().GetStartupInfo();
                resp = CreateTaskResponse(
                    $"x64 Startup Information set to: {sacParams.Application} {sacParams.Arguments}",
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