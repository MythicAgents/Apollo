#define COMMAND_NAME_UPPER

#if DEBUG
#define TICKET_STORED_ADD
#endif

#if TICKET_STORED_ADD

using System;
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
            //make a placeholder ticket for now
            KerberosTicket ticket = new()
            {
                Luid = new(),
                ClientName = "test",
                ClientRealm = "test",
                ServerName = "test",
                ServerRealm = "test",
                StartTime = DateTime.Now,
                EndTime = DateTime.Now,
                RenewTime = DateTime.Now,
                EncryptionType = KerbEncType.des3_cbc_md5,
                TicketFlags = KerbTicketFlags.Initial,
                Kirbi = ticketBytes
            };
            
            _agent.GetTicketManager().AddTicketToTicketStore(new KerberosTicketStoreDTO(ticket));
            resp = CreateTaskResponse($"Added Ticket to Ticket Store", true);
        }
        catch (Exception e)
        {
            resp = CreateTaskResponse($"Failed to inject ticket into session: {e.Message}", true, "error");
        }
        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
    }
}
#endif