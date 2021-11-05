﻿#define COMMAND_NAME_UPPER

#if DEBUG
#define WHOAMI
#endif

#if WHOAMI

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class whoami : Tasking
    {
        public whoami(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
        }

        public override void Kill()
        {
            base.Kill();
        }

        public override ST.Task CreateTasking()
        {
            return new ST.Task(() =>
            {
                TaskResponse resp = CreateTaskResponse(
                    WindowsIdentity.GetCurrent().Name, true);
                // Your code here..
                // Then add response to queue
                // _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            }, _cancellationToken.Token);
        }
    }
}

#endif