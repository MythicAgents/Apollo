using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;
using ApolloInterop.Serializers;
using System.Threading;
using System.IO;

namespace Tasks
{
    public class cd : Tasking
    {
        public cd(IAgent agent, Task task) : base(agent, task)
        {

        }

        public override void Kill()
        {
            _cancellationToken.Cancel();
        }

        public override System.Threading.Tasks.Task CreateTasking()
        {
            return new System.Threading.Tasks.Task(() =>
            {
                if (!Directory.Exists(_data.Parameters))
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                        $"Directory {_data.Parameters} does not exist",
                        true,
                        "error"));
                } else
                {
                    Directory.SetCurrentDirectory(_data.Parameters);
                    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                        $"Working directory set to {Directory.GetCurrentDirectory()}",
                        true));
                }
            }, _cancellationToken.Token);
        }
    }
}
