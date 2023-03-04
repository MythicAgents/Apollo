#define COMMAND_NAME_UPPER

#if DEBUG
#define CD
#endif

#if CD

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
    public class cd : Tasking
    {
        [DataContract]
        public struct CdParameters
        {
            [DataMember(Name = "path")] public string Path;
        }
        public cd(IAgent agent, Task task) : base(agent, task)
        {

        }

        public override void Start()
        {
            CdParameters parameters = _jsonSerializer.Deserialize<CdParameters>(_data.Parameters);
            if (!Directory.Exists(parameters.Path))
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                    $"Directory {parameters.Path} does not exist",
                    true,
                    "error"));
            }
            else
            {
                Directory.SetCurrentDirectory(parameters.Path);
                _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                    $"Working directory set to {Directory.GetCurrentDirectory()}",
                    true));
            }
        }
    }
}
#endif