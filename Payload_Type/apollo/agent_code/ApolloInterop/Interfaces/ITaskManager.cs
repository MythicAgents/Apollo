using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Types.Delegates;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Enums.ApolloEnums;

namespace ApolloInterop.Interfaces
{
    public interface ITaskManager
    {
        bool CreateTaskingMessage(OnResponse<TaskingMessage> onResponse);

        bool ProcessMessageResponse(MessageResponse resp);

        void AddTaskResponseToQueue(TaskResponse message);

        void AddDelegateMessageToQueue(DelegateMessage delegateMessage);

        void AddSocksDatagramToQueue(MessageDirection dir, SocksDatagram dg);
    }
}
