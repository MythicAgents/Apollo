using System;
using System.Collections.Generic;
using System.Linq;
using ApolloInterop.Features.KerberosTickets;
using ApolloInterop.Features.WindowsTypesAndAPIs;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;

namespace KerberosTickets;

public class KerberosTicketManager : ITicketManager
{
    /// <summary>
    /// Instance of the Agent class which is passed in during the Start call of the primary application
    /// This will never be null as it is set in the constructor during startup of the main app
    /// Is used to access varoius API's and other features of the main application & Interop library
    /// </summary>
    internal static IAgent Agent { get; private set;} = null!;
    
    internal List<KerberosTicketStoreDTO> loadedTickets = new List<KerberosTicketStoreDTO>();

    
    public KerberosTicketManager(IAgent agent)
    {
        Agent = agent;
        WindowsAPI.Initialize();
        DebugHelp.DebugWriteLine("KerberosTicketManager initialized");
    }


    public List<Artifact> GetArtifacts() => KerberosHelpers.GetCreatedArtifacts();
    public string GetCurrentLuid() => KerberosHelpers.GetCurrentLuid().ToString();
    
    public string GetTargetProcessLuid(int pid) => KerberosHelpers.GetTargetProcessLuid(pid).ToString();
    
    //ticket cache functions, these effect the session on the system
    public KerberosTicket? ExtractTicketFromCache(string luid, string serviceName) => KerberosHelpers.ExtractTicket(WinNTTypes.LUID.FromString(luid), serviceName);
    public List<KerberosTicket> EnumerateTicketsInCache(bool getSystemTickets = false, string luid = "") => KerberosHelpers.TriageTickets(getSystemTickets,luid).ToList();
    
    public bool LoadTicketIntoCache(byte[] ticket, string luid) => KerberosHelpers.LoadTicket(ticket, WinNTTypes.LUID.FromString(luid));
    
    public bool UnloadTicketFromCache(string serviceName, string domainName, string luid, bool All = false) =>  KerberosHelpers.UnloadTicket(serviceName, domainName, WinNTTypes.LUID.FromString(luid), All);
    
    public KerberosTicket? GetTicketDetailsFromKirbi(byte[] kirbi) => KerberosHelpers.TryGetTicketDetailsFromKirbi(kirbi);
    
    
    //Ticket Store Functions, these only effect the in memory ticket store
    public List<KerberosTicketStoreDTO> GetTicketsFromTicketStore() => loadedTickets;
    
    public void AddTicketToTicketStore(KerberosTicketStoreDTO ticket) => loadedTickets.Add(ticket);

    public bool RemoveTicketFromTicketStore(string serviceName, bool All = false) 
        => All ? loadedTickets.RemoveAll(_ => true) > 0  
            : loadedTickets.RemoveAll(x => x.ServiceFullName.Equals(serviceName, StringComparison.CurrentCultureIgnoreCase)) > 0;

}