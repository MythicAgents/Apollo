#define COMMAND_NAME_UPPER

#if DEBUG
#define REGISTER_FILE
#endif

#if REGISTER_FILE


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
    public class register_file : Tasking
    {
        [DataContract]
        internal struct RegisterFileParameters
        {
            [DataMember(Name = "file_id")]
            internal string FileID;
            [DataMember(Name = "file_name")]
            internal string FileName;
        }

        public register_file(IAgent agent, Task task) : base(agent, task)
        {

        }


        public override void Start()
        {
            TaskResponse resp;
            RegisterFileParameters parameters = _jsonSerializer.Deserialize<RegisterFileParameters>(_data.Parameters);
            // some additional upload logic
            if (_agent.GetFileManager().GetFile(
                    _cancellationToken.Token,
                    _data.ID,
                    parameters.FileID,
                    out byte[] fileData))
            {
                if (parameters.FileName.EndsWith(".ps1"))
                {
                    _agent.GetFileManager().SetScript(fileData);
                    resp = CreateTaskResponse(
                        $"{parameters.FileName} will now be imported in PowerShell commands.", true);
                }
                else
                {
                    if (_agent.GetFileManager().AddFileToStore(parameters.FileName, fileData))
                    {
                        resp = CreateTaskResponse(
                            $"{parameters.FileName} has been registered.",
                            true);
                    }
                    else
                    {
                        resp = CreateTaskResponse(
                            $"Failed to register {parameters.FileName}",
                            true,
                            "error");
                    }
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
        }
    }
}
#endif