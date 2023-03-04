#define COMMAND_NAME_UPPER

#if DEBUG
#define UPLOAD
#endif

#if UPLOAD

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
using System.Security.Principal;

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

        internal string ParsePath(UploadParameters p)
        {
            string host = "";
            string path = "";
            if (!string.IsNullOrEmpty(p.HostName))
            {
                if (p.HostName != "127.0.0.1" || p.HostName.ToLower() != "localhost")
                {
                    host = p.HostName;
                }
            }
            if (!string.IsNullOrEmpty(p.RemotePath))
            {
                if (Directory.Exists(p.RemotePath))
                {
                    path = Path.Combine(new string[]
                    {
                        p.RemotePath,
                        p.FileName
                    });
                } else
                {
                    path = p.RemotePath;
                }
            } else
            {
                path = Path.Combine(new string[]
                {
                    Directory.GetCurrentDirectory(),
                    p.FileName
                });
            }

            if (!string.IsNullOrEmpty(host))
            {
                return string.Format(@"\\{0}\{1}", host, path);
            } else
            {
                FileInfo finfo = new FileInfo(path);
                return finfo.FullName;
            }
        }


        public override void Start()
        {
            TaskResponse resp;
            UploadParameters parameters = _jsonSerializer.Deserialize<UploadParameters>(_data.Parameters);
            // some additional upload logic
            if (_agent.GetFileManager().GetFile(
                    _cancellationToken.Token,
                    _data.ID,
                    parameters.FileID,
                    out byte[] fileData))
            {
                string path = ParsePath(parameters);
                try
                {
                    File.WriteAllBytes(path, fileData);

                    resp = CreateTaskResponse(
                        $"Uploaded {fileData.Length} bytes to {path}",
                        true,
                        "completed",
                        new IMythicMessage[]
                        {
                            new UploadMessage()
                            {
                                FileID = parameters.FileID,
                                FullPath = path
                            },
                            Artifact.FileWrite(path, fileData.Length)
                        });
                }
                catch (Exception ex)
                {
                    resp = CreateTaskResponse($"Failed to upload file: {ex.Message}", true, "error");
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