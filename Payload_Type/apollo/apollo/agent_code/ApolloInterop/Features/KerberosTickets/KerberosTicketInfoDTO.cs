using System;
using System.Runtime.Serialization;

namespace ApolloInterop.Features.KerberosTickets;
[DataContract]
public record KerberosTicketInfoDTO
{
    [DataMember(Name = "luid")]
    public string Luid { get; private set; }
    [DataMember(Name = "current_luid")]
    public string CurrentLuid {get; set; }
    [DataMember(Name = "client_name")]
    public string ClientName { get; private set; }
    [DataMember(Name = "client_realm")]
    public string ClientDomain { get; private set; }

    public string ClientFullName => $"{ClientName}@{ClientDomain}";
    [DataMember(Name = "service_name")]
    public string ServiceName { get; private set; }
    [DataMember(Name = "service_realm")]
    public string ServiceDomain { get; private set; }

    public string ServiceFullName => $"{ServiceName}@{ServiceDomain}";
    [DataMember(Name = "start_time")]
    public string StartTimeDisplay { get; private set; }
    public DateTime StartTime { get; private set; }
    [DataMember(Name = "end_time")]
    public string EndTimeDisplay { get; private set; }
    public DateTime EndTime { get; private set; }

    public string TimeUntilExpiration => (EndTime.ToUniversalTime() - DateTime.UtcNow).ToString(@"dd\.hh\:mm\:ss");
    [DataMember(Name = "renew_time")]
    public string RenewTimeDisplay { get; private set; }
    public DateTime RenewTime { get; private set; }

    public string TimeUntilRenewal => (RenewTime.ToUniversalTime() - DateTime.UtcNow).ToString(@"dd\.hh\:mm\:ss");
    [DataMember(Name = "encryption_type")]
    public string EncryptionTypeDisplay { get; private set; }
    public KerbEncType EncryptionType { get; private set; }
    [DataMember(Name = "ticket_flags")]
    public string TicketFlagsDisplay { get; private set; }
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
            StartTimeDisplay = ticket.StartTime.ToString(),
            EndTime = ticket.EndTime,
            EndTimeDisplay = ticket.EndTime.ToString(),
            RenewTime = ticket.RenewTime,
            RenewTimeDisplay = ticket.RenewTime.ToString(),
            EncryptionType = ticket.EncryptionType,
            EncryptionTypeDisplay = ticket.EncryptionType.ToString(),
            TicketFlags = ticket.TicketFlags,
            TicketFlagsDisplay = ticket.TicketFlags.ToString(),
        };
    }
}