#define COMMAND_NAME_UPPER

#if DEBUG
#define JOBS
#endif

#if JOBS

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Collections.Generic;

namespace Tasks
{
    public class jobs : Tasking
    {
        public jobs(IAgent agent, MythicTask data) : base(agent, data)
        {
        }
        
        public override void Start()
        {
            string[] jids = _agent.GetTaskManager().GetExecutingTaskIds();
            string fmtArr = "[";
            List<string> realJids = new List<string>();
            foreach (string j in jids)
            {
                if (j != _data.ID)
                {
                    realJids.Add(j);
                }
            }

            MythicTaskResponse resp = CreateTaskResponse("", true, "completed");
            resp.ProcessResponse = new ApolloInterop.Structs.ApolloStructs.ProcessResponse
            {
                Jobs = realJids.ToArray()
            };
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif