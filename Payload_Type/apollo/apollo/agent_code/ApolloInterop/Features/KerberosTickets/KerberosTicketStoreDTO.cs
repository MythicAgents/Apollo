using System;

namespace ApolloInterop.Features.KerberosTickets;

//for the moment this is the same as the KerberosTicketDataDTO, but it will be used for the store so more / different fileds may be added that are unique to the store
public record KerberosTicketStoreDTO
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
        
        
        public KerberosTicketStoreDTO(KerberosTicket ticket)
        {
            Luid = ticket.Luid.ToString();
            ClientFullName = $"{ticket.ClientName}@{ticket.ClientRealm}";
            ServiceFullName = $"{ticket.ServerName}@{ticket.ServerRealm}";
            StartTime = ticket.StartTime;
            EndTime = ticket.EndTime;
            RenewTime = ticket.RenewTime;
            EncryptionType = ticket.EncryptionType;
            TicketFlags = ticket.TicketFlags;
            base64Ticket = Convert.ToBase64String(ticket.Kirbi);
        }
    
}