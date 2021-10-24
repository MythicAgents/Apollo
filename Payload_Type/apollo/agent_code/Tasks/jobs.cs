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
    public class jobs : Tasking
    {
        public jobs(IAgent agent, Task data) : base(agent, data)
        {
        }

        public override ST.Task CreateTasking()
        {
            return new ST.Task(() =>
            {
                string[] jids = _agent.GetTaskManager().GetExecutingTaskIds();
                string fmtArr = "[";
                List<string> realJids = new List<string>();
                foreach(string j in jids)
                {
                    if (j != _data.ID)
                    {
                        realJids.Add(j);
                    }
                }
                for(int i = 0; i < realJids.Count; i++)
                {
                    if (i == realJids.Count - 1)
                    {
                        fmtArr += $"\"{realJids[i]}\"";
                    } else
                    {
                        fmtArr += $"\"{realJids[i]}\", ";
                    }
                }
                fmtArr += "]";
                string jstr = "{\"jobs\": " + fmtArr + "}";
                _agent.GetTaskManager().AddTaskResponseToQueue(
                    CreateTaskResponse(
                        jstr,
                        true));
            }, _cancellationToken.Token);
        }
    }
}
