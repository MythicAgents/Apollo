#define COMMAND_NAME_UPPER

#if DEBUG
#define TICKET_STORED_LIST
#endif

#if TICKET_STORED_LIST

using System;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;

namespace Tasks;

public class ticket_store_list : Tasking
{

    public ticket_store_list(IAgent agent, MythicTask data) : base(agent, data)
    { }
    public override void Start()
    {
        MythicTaskResponse resp = new MythicTaskResponse { };
        try
        {
           var storedTickets =   _agent.GetTicketManager().GetTicketsFromTicketStore();
           StringBuilder ticketStringOutput = new StringBuilder();
           for(int i = 0; i < storedTickets.Count; i++)
           {
               ticketStringOutput.AppendLine($"Store Ticket # {i}:");
               ticketStringOutput.Append(storedTickets[i].ToString().ToIndentedString());
               ticketStringOutput.Append("\n");
           }
           resp = CreateTaskResponse($"Enumerated Tickets \n {ticketStringOutput}", true);
            
        }
        catch (Exception ex)
        {
           resp = CreateTaskResponse($"Error in {this.GetType().Name} - {ex.Message}", true, "error");
            
        }
        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
    }
}
#endif