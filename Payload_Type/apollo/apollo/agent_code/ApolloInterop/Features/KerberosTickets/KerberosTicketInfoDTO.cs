using System;

namespace ApolloInterop.Features.KerberosTickets;

public record KerberosTicketInfoDTO
{
    public string Luid { get; private set; }
    public string ClientName { get; private set; }
    public string ClientDomain { get; private set; }
    
    public string ClientFullName => $"{ClientName}@{ClientDomain}";
    public string ServiceName { get; private set; }
    public string ServiceDomain { get; private set; }
    
    public string ServiceFullName => $"{ServiceName}@{ServiceDomain}";
    public DateTime StartTime { get; private set; }
    public DateTime EndTime { get; private set; }
    
    public string TimeUntilExpiration => (EndTime.ToUniversalTime() - DateTime.UtcNow).ToString(@"dd\.hh\:mm\:ss");
    public DateTime RenewTime { get; private set; }
    
    public string TimeUntilRenewal => (RenewTime.ToUniversalTime() - DateTime.UtcNow).ToString(@"dd\.hh\:mm\:ss");
    public KerbEncType EncryptionType { get; private set; }
    public KerbTicketFlags TicketFlags { get; private set; }
    
    
    private KerberosTicketInfoDTO() { }
    
    public static KerberosTicketInfoDTO CreateFromKerberosTicket(KerberosTicket ticket)
    {
        return new KerberosTicketInfoDTO
        {
            Luid = ticket.Luid.ToString(),
            ClientName = ticket.ClientName,
            ClientDomain = ticket.ClientRealm,
            ServiceName = ticket.ServerName,
            ServiceDomain = ticket.ServerRealm,
            StartTime = ticket.StartTime,
            EndTime = ticket.EndTime,
            RenewTime = ticket.RenewTime,
            EncryptionType = ticket.EncryptionType,
            TicketFlags = ticket.TicketFlags,
        };
    }
}