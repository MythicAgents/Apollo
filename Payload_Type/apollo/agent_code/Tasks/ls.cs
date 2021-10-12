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
using System.Security.AccessControl;

namespace Tasks
{
    public class ls : Tasking
    {
        private static ACE GetAceInformation(FileSystemAccessRule ace)
        {
            ACE result = new ACE
            {
                Account = ace.IdentityReference.Value,
                Type = ace.AccessControlType.ToString(),
                Rights = ace.FileSystemRights.ToString(),
                IsInherited = ace.IsInherited
            };
            return result;
        }

        private static ACE[] GetPermissions(FileInfo fi)
        {
            List<ACE> permissions = new List<ACE>();
            try
            {
                FileSecurity fsec = fi.GetAccessControl(AccessControlSections.Access);
                foreach (FileSystemAccessRule FSAR in fsec.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
                {
                    var tmp = GetAceInformation(FSAR);
                    permissions.Add(tmp);
                }
            }
            catch { }

            return permissions.ToArray();
        }
        private static ACE[] GetPermissions(DirectoryInfo di)
        {
            List<ACE> permissions = new List<ACE>();
            try
            {
                DirectorySecurity DirSec = di.GetAccessControl(AccessControlSections.Access);
                foreach (FileSystemAccessRule FSAR in DirSec.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
                {
                    var tmp = GetAceInformation(FSAR);
                    permissions.Add(tmp);
                }
            }
            catch { }

            return permissions.ToArray();
        }

        private static string[] localhostAliases = new string[]
        {
            "localhost",
            "127.0.0.1",
            Environment.GetEnvironmentVariable("COMPUTERNAME").ToLower()
        };
        [DataContract]
        internal struct LsParameters
        {
            [DataMember(Name = "host")]
            public string Host;
            [DataMember(Name = "path")]
            public string Path;
        }


        public ls(IAgent agent, Task task) : base(agent, task)
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
                LsParameters parameters = _jsonSerializer.Deserialize<LsParameters>(_data.Parameters);
                string host = localhostAliases.Contains(parameters.Host.ToLower()) ? "" : parameters.Host;
                string path = string.IsNullOrEmpty(host) ?
                              parameters.Path : $@"\\{host}\{parameters.Path}";
                if (string.IsNullOrEmpty(path))
                    path = ".";
                if (string.IsNullOrEmpty(host))
                    host = Environment.GetEnvironmentVariable("COMPUTERNAME");
                FileBrowser results = new FileBrowser
                {
                    Host = host
                };
                string errorMessage = "";
                bool bRet = true;
                List<FileInformation> files = new List<FileInformation>();
                if (File.Exists(path))
                {
                    try
                    {
                        var tmp = new FileInfo(path);
                        FileInformation finfo = new FileInformation(tmp, null);
                        results.IsFile = true;
                        results.Name = finfo.Name;
                        results.ParentPath = finfo.Directory;
                        results.AccessTime = finfo.AccessTime;
                        results.ModifyTime = finfo.ModifyTime;
                        results.Size = finfo.Size;
                        try
                        {
                            results.Permissions = GetPermissions(tmp);
                        } catch { }
                        files.Add(finfo);
                    } catch (Exception ex)
                    {
                        bRet = false;
                        errorMessage = $"Failed to get information on file {path}: {ex.Message}\n\n{ex.StackTrace}";
                    }
                } else if (Directory.Exists(path))
                {
                    try
                    {
                        DirectoryInfo dinfo = new DirectoryInfo(path);
                        FileInformation finfo = new FileInformation(dinfo, null);
                        results.IsFile = false;
                        results.Name = finfo.Name;
                        results.ParentPath = dinfo.Parent == null ? "" : dinfo.Parent.FullName;
                        results.AccessTime = finfo.AccessTime;
                        results.ModifyTime = finfo.ModifyTime;
                        results.Size = finfo.Size;
                        try
                        {
                            results.Permissions = GetPermissions(dinfo);
                        } catch { }
                        string[] directories = Directory.GetDirectories(path);
                        for(int i = 0; i < directories.Length && !_cancellationToken.IsCancellationRequested; i++)
                        {
                            string dir = directories[i];
                            try
                            {
                                var tmp = new DirectoryInfo(dir);
                                FileInformation dirInfo = new FileInformation(tmp, null);
                                try
                                {
                                    dirInfo.Permissions = GetPermissions(tmp);
                                } catch { }
                                files.Add(dirInfo);
                            } catch { }
                        }
                        string[] dirFiles = Directory.GetFiles(path);
                        for(int i = 0; i < dirFiles.Length && !_cancellationToken.IsCancellationRequested; i++)
                        {
                            string f = dirFiles[i];
                            try
                            {
                                var tmp = new FileInfo(f);
                                FileInformation newFinfo = new FileInformation(tmp, null);
                                try
                                {
                                    newFinfo.Permissions = GetPermissions(tmp);
                                } catch { }
                                files.Add(newFinfo);
                            } catch { }
                        }
                    } catch (Exception ex)
                    {
                        bRet = false;
                        errorMessage = $"Failed to get information on directory {path}: {ex.Message}\n\n{ex.StackTrace}";
                    }
                } else
                {
                    bRet = false;
                    errorMessage = $"Could not find file or directory {path}";
                }

                results.Success = bRet;
                results.Files = files.ToArray();

                TaskResponse resp = CreateTaskResponse(
                        bRet ? "" : errorMessage,
                        true,
                        bRet ? "completed" : "error",
                        new IMythicMessage[]
                        {
                            results
                        });
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }, _cancellationToken.Token);
        }
    }
}
