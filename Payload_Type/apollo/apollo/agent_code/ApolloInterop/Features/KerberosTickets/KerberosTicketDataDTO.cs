using System;

namespace ApolloInterop.Features.KerberosTickets;

public record KerberosTicketDataDTO
{
    public string Luid { get; private set; }
    
    public string ClientFullName { get; private set; }
    
    public string ServiceFullName { get; private set; }
    public DateTime StartTime { get; private set; }
    public DateTime EndTime { get; private set; }
    
    public string TimeUntilExpiration => (EndTime.ToUniversalTime() - DateTime.UtcNow).ToString(@"dd\.hh\:mm\:ss");
    public DateTime RenewTime { get; private set; }
    
    public string TimeUntilRenewal => (RenewTime.ToUniversalTime() - DateTime.UtcNow).ToString(@"dd\.hh\:mm\:ss");
    public KerbEncType EncryptionType { get; private set; }
    public KerbTicketFlags TicketFlags { get; private set; }
    public string base64Ticket { get; private set; }
    
    
    private KerberosTicketDataDTO() { }
    
    public static KerberosTicketDataDTO CreateFromKerberosTicket(KerberosTicket ticket, string luid = "0x0")
    {
        return new KerberosTicketDataDTO
        {
            Luid = ticket.Luid.ToString() is "0x0" ?  luid : ticket.Luid.ToString(),
            ClientFullName = $"{ticket.ClientName}@{ticket.ClientRealm}",
            ServiceFullName = $"{ticket.ServerName}@{ticket.ServerRealm}",
            StartTime = ticket.StartTime,
            EndTime = ticket.EndTime,
            RenewTime = ticket.RenewTime,
            EncryptionType = ticket.EncryptionType,
            TicketFlags = ticket.TicketFlags,
            base64Ticket = Convert.ToBase64String(ticket.Kirbi)
        };
    }
}