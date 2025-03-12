using System;
using System.Runtime.Serialization;

namespace ApolloInterop.Features.KerberosTickets;

//for the moment this is the same as the KerberosTicketDataDTO, but it will be used for the store so more / different fileds may be added that are unique to the store
[DataContract]
public record KerberosTicketStoreDTO
{
    [DataMember(Name = "luid")]
    public string Luid { get; private set; }
    [DataMember(Name = "client_fullname")]
    public string ClientFullName { get; private set; }
    [DataMember(Name = "service_fullname")]
    public string ServiceFullName { get; private set; }
    [DataMember(Name = "start_time")]
    public string StartTimeDisplay { get; private set; }
    public DateTime StartTime;
    [DataMember(Name = "end_time")]
    public string EndTimeDisplay { get; private set; }
    public DateTime EndTime;
    public string TimeUntilExpiration => (EndTime.ToUniversalTime() - DateTime.UtcNow).ToString(@"dd\.hh\:mm\:ss");
    [DataMember(Name = "renew_time")]
    public string RenewTimeDisplay { get; private set; }
    public DateTime RenewTime;
    public string TimeUntilRenewal => (RenewTime.ToUniversalTime() - DateTime.UtcNow).ToString(@"dd\.hh\:mm\:ss");
    public KerbEncType EncryptionType;
    [DataMember(Name = "encryption_type")]
    public string EncryptionTypeDisplay { get; private set; }
    [DataMember(Name = "ticket_flags")]
    public string TicketFlagsDisplay { get; private set; }
    public KerbTicketFlags TicketFlags;
    [DataMember(Name = "ticket")]
    public string base64Ticket { get; private set; }


    public KerberosTicketStoreDTO(KerberosTicket ticket)
    {
        Luid = ticket.Luid.ToString();
        ClientFullName = $"{ticket.ClientName}@{ticket.ClientRealm}";
        ServiceFullName = $"{ticket.ServerName}@{ticket.ServerRealm}";
        StartTime = ticket.StartTime;
        StartTimeDisplay = StartTime.ToString();
        EndTime = ticket.EndTime;
        EndTimeDisplay = EndTime.ToString();
        RenewTime = ticket.RenewTime;
        RenewTimeDisplay = RenewTime.ToString();
        EncryptionType = ticket.EncryptionType;
        EncryptionTypeDisplay = ticket.EncryptionType.ToString();
        TicketFlags = ticket.TicketFlags;
        TicketFlagsDisplay = ticket.TicketFlags.ToString();
        base64Ticket = Convert.ToBase64String(ticket.Kirbi);
    }
    
}