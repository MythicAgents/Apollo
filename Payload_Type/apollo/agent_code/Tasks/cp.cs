#define COMMAND_NAME_UPPER

#if DEBUG
#define CP
#endif

#if CP

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
    public class cp : Tasking
    {
        [DataContract]
        internal struct CpParameters
        {
            [DataMember(Name = "source")]
            public string SourceFile;
            [DataMember(Name = "destination")]
            public string DestinationFile;
        }
        public cp(IAgent agent, Task task) : base(agent, task)
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
                CpParameters parameters = _jsonSerializer.Deserialize<CpParameters>(_data.Parameters);
                TaskResponse resp;
                try
                {
                    File.Copy(parameters.SourceFile, parameters.DestinationFile);
                    FileInfo source = new FileInfo(parameters.SourceFile);
                    FileInfo dest = new FileInfo(parameters.DestinationFile);
                    resp = CreateTaskResponse(
                        $"Copied {source.FullName} to {source.FullName}",
                        true,
                        "completed",
                        new IMythicMessage[1]
                        {
                            new Artifact
                            {
                                BaseArtifact = "FileWrite",
                                ArtifactDetails = $"Wrote {source.Length} to {dest.FullName}"
                            }
                        });
                } catch (Exception ex)
                {
                    resp = CreateTaskResponse($"Failed to copy file: {ex.Message}", true, "error");
                }
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }, _cancellationToken.Token);
        }
    }
}
#endif