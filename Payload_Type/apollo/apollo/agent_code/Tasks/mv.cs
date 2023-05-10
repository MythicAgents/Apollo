#define COMMAND_NAME_UPPER

#if DEBUG
#define MV
#endif

#if MV

using System;
using System.IO;
using System.Runtime.Serialization;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;
using ST = System.Threading.Tasks;


namespace Tasks
{
    public class mv : Tasking
    {
        public mv(IAgent agent, Task data) : base(agent, data)
        {
        }

        private HostFileInfo ParsePath(string path)
        {
            var results = new HostFileInfo();
            results.Host = Environment.GetEnvironmentVariable("COMPUTERNAME");
            results.Path = path;
            if (path.StartsWith("\\\\")) results.Host = path.Split('\\')[2];

            return results;
        }

        public override void Start()
        {
            TaskResponse resp;
            HostFileInfo sourceInfo;
            var parameters = _jsonSerializer.Deserialize<MvParameters>(_data.Parameters);

            if (!PathUtils.TryGetExactPath(parameters.SourceFile, out _))
            {
                resp = CreateTaskResponse(
                    $"File {parameters.SourceFile} does not exist.",
                    true, "error");
            }
            else
            {
                var isDir = false;
                FileSystemInfo sinfo = null;
                FileInformation dinfo;
                if (Directory.Exists(parameters.SourceFile))
                {
                    sinfo = new DirectoryInfo(parameters.SourceFile);
                    isDir = true;
                }
                else
                {
                    sinfo = new FileInfo(parameters.SourceFile);
                }

                try
                {
                    if (isDir)
                        Directory.Move(parameters.SourceFile, parameters.DestinationFile);
                    else
                        File.Move(parameters.SourceFile, parameters.DestinationFile);

                    dinfo = !isDir
                        ? new FileInformation(new FileInfo(parameters.DestinationFile))
                        : new FileInformation(new DirectoryInfo(parameters.DestinationFile));
                    sourceInfo = ParsePath(parameters.SourceFile);
                    ParsePath(parameters.DestinationFile);
                    resp = CreateTaskResponse(
                        $"Moved {sinfo.FullName} to {dinfo.FullName}",
                        true,
                        "completed",
                        new IMythicMessage[]
                        {
                            Artifact.FileOpen(sinfo.FullName),
                            Artifact.FileDelete(sinfo.FullName),
                            Artifact.FileOpen(dinfo.FullName),
                            Artifact.FileWrite(dinfo.FullName, isDir ? 0 : dinfo.Size),
                            new FileBrowser(dinfo)
                        });
                    resp.RemovedFiles = new[]
                    {
                        new RemovedFileInformation
                        {
                            Host = sourceInfo.Host,
                            Path = sinfo.FullName
                        }
                    };
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
        }

        [DataContract]
        internal struct MvParameters
        {
            [DataMember(Name = "source")] public string SourceFile;
            [DataMember(Name = "destination")] public string DestinationFile;
        }

        internal struct HostFileInfo
        {
            internal string Host;
            internal string Path;
        }
    }
}

#endif