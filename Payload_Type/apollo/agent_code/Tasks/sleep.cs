#define COMMAND_NAME_UPPER

#if DEBUG
#define SLEEP
#endif

#if SLEEP

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
    public class sleep : Tasking
    {
        public sleep(IAgent agent, Task data) : base(agent, data)
        {
        }


        public override void Start()
        {
            TaskResponse resp;
            string[] parts = _data.Parameters.Split(' ');
            int sleepTime = -1;
            double jitterTime = -1;
            if (int.TryParse(parts[0], out sleepTime))
            {
                if (parts.Length > 1 && double.TryParse(parts[1], out jitterTime))
                {
                    resp = CreateTaskResponse("", true);
                }
                else
                {
                    resp = CreateTaskResponse("", true);
                }
            }
            else
            {
                resp = CreateTaskResponse($"Failed to parse int from {parts[0]}.", true, "error");
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            if (sleepTime >= 0)
            {
                if (jitterTime >= 0)
                {
                    _agent.SetSleep(sleepTime, jitterTime);
                }
                else
                {
                    _agent.SetSleep(sleepTime);
                }
            }
        }
    }
}
#endif