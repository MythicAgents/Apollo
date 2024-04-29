using System.Collections.Generic;

namespace ApolloInterop.Features.KerberosTickets;

/// <summary>
/// Should serve to manage kerberos tickets.
/// Any functions I want to enable calling from other modules like Tasks should be defined here.
/// </summary>
public interface ITicketManager
{
    //returns the current LUID
    public string GetCurrentLuid();
    
    public string GetTargetProcessLuid(int pid);
    
    //should return a ticket with the .kirbi initalized with the ticket data
    public KerberosTicket ExtractTicketFromCache(string luid, string serviceName);
    //should return all tickets in the current LUID or all tickets if running as administrator
    public List<KerberosTicket> EnumerateTicketsInCache(bool getSystemTickets = false, string luid = "");
    //loads a ticket into memory and should be tracked by the agent session
    public bool LoadTicketIntoCache(byte[] ticket, string luid);
    //unloads a ticket from memory and should be removed from the agent session
    public bool UnloadTicketFromCache(byte[] ticket, string luid, bool All = false);
   
    
    //returns a list of tickets stored inside the ticket store (if any) 
    public List<KerberosTicketStoreDTO> GetTicketsFromTicketStore();
    //adds a ticket to the ticket store
    public void AddTicketToTicketStore(KerberosTicketStoreDTO ticket);
    //removes a ticket from the ticket store
    public bool RemoveTicketFromTicketStore(string b64ticket,bool All = false);
    



}