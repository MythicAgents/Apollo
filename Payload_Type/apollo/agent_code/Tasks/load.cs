#define COMMAND_NAME_UPPER

#if DEBUG
#define LOAD
#endif

#if LOAD

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using ApolloInterop.Structs.ApolloStructs;
using ST = System.Threading.Tasks;
namespace Tasks
{
    public class load : Tasking
    {
        [DataContract]
        internal struct LoadParameters
        {
            [DataMember(Name = "commands")]
            public string[] Commands;
            [DataMember(Name = "file_id")]
            public string FileId;
        }
        public load(IAgent agent, Task data) : base(agent, data)
        {
            
        }

        public override ST.Task CreateTasking()
        {
            return new ST.Task(() => { Start(); }, _cancellationToken.Token);
        }

        public override void Start()
        {
            TaskResponse resp;
            LoadParameters parameters = _jsonSerializer.Deserialize<LoadParameters>(_data.Parameters);
            if (parameters.Commands.Length == 0)
            {
                resp = CreateTaskResponse("No commands given to load.", true, "error");
            }
            else if (string.IsNullOrEmpty(parameters.FileId))
            {
                resp = CreateTaskResponse("No task library file given to retrieve.", true, "error");
            }
            else
            {
                if (_agent.GetFileManager().GetFile(
                        _cancellationToken.Token,
                        _data.ID,
                        parameters.FileId,
                        out byte[] taskLib))
                {
                    if (_agent.GetTaskManager().LoadTaskModule(taskLib, parameters.Commands))
                    {
                        IMythicMessage[] items = new IMythicMessage[parameters.Commands.Length];
                        for (int i = 0; i < items.Length; i++)
                        {
                            items[i] = new CommandInformation
                            {
                                Action = "add",
                                Command = parameters.Commands[i]
                            };
                        }

                        resp = CreateTaskResponse(
                            $"",
                            true,
                            "completed",
                            items);
                        resp.ProcessResponse = new ProcessResponse()
                        {
                            Commands = parameters.Commands
                        };
                    }
                    else
                    {
                        resp = CreateTaskResponse(
                            $"One or more commands were not found in the task library.",
                            true,
                            "error");
                    }
                }
                else
                {
                    resp = CreateTaskResponse("Failed to pull down task library.", true, "error");
                }
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif