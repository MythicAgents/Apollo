#define COMMAND_NAME_UPPER

#if DEBUG
#define KILL
#endif

#if KILL

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class kill : Tasking
    {
        [DataContract]
        internal struct KillArguments
        {
            [DataMember(Name = "pid")]
            public int PID;
        }
        public kill(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
        }


        public override void Start()
        {
            TaskResponse resp;
            KillArguments parameters = _jsonSerializer.Deserialize<KillArguments>(_data.Parameters);
            try
            {
                System.Diagnostics.Process proc = System.Diagnostics.Process.GetProcessById(parameters.PID);
                proc.Kill();
                resp = CreateTaskResponse($"Killed {proc.ProcessName} ({proc.Id})", true, "completed",
                    new IMythicMessage[]
                    {
                        Artifact.ProcessKill(proc.Id)
                    });
            }
            catch (Exception ex)
            {
                resp = CreateTaskResponse($"Failed to kill process. Reason: {ex.Message}", true, "error");
            }

            // Your code here..
            // Then add response to queue
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif