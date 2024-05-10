#define COMMAND_NAME_UPPER

#if DEBUG
#define TICKET_CACHE_PURGE
#endif

#if TICKET_CACHE_PURGE

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;

namespace Tasks;

public class ticket_cache_purge : Tasking
{
    
    [DataContract]
    internal struct ticket_cache_purgeParameters
    {
        [DataMember(Name = "luid")]
        internal string? luid;
        [DataMember(Name = "serviceName")]
        internal string? serviceName;
        [DataMember(Name = "all")]
        internal bool all;
    }

    public ticket_cache_purge(IAgent agent, MythicTask data) : base(agent, data)
    { }
    public override void Start()
    {
        MythicTaskResponse resp = new MythicTaskResponse { };
        try
        {
            ticket_cache_purgeParameters parameters = _jsonSerializer.Deserialize<ticket_cache_purgeParameters>(_data.Parameters);
            string luid = parameters.luid ?? "";
            string? serviceFullName = parameters.serviceName ?? "";
            string serviceName = String.IsNullOrWhiteSpace(serviceFullName) ? "" : serviceFullName.Split('@').First();
            string domainName = String.IsNullOrWhiteSpace(serviceFullName) ? "" : serviceFullName.Split('@').Last();
            bool all = parameters.all;
            
            bool ticketRemoved = _agent.GetTicketManager().UnloadTicketFromCache(serviceName,domainName, luid, all);
            //if true return without error if false return with error
            resp = ticketRemoved ? CreateTaskResponse($"Purged Ticket from Cache", true) 
                : CreateTaskResponse($"Failed to remove ticket from Cache", true, "error");

        }
        catch (Exception e)
        {
            resp = CreateTaskResponse($"Failed to remove ticket from session: {e.Message}", true, "error");
        }
        //get and send back any artifacts
        IEnumerable<Artifact> artifacts = _agent.GetTicketManager().GetArtifacts();
        var artifactResp = CreateArtifactTaskResponse(artifacts);
        _agent.GetTaskManager().AddTaskResponseToQueue(artifactResp);

        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
    }
}
#endif