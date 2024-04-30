using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using ApolloInterop.Enums;
using ApolloInterop.Features.WindowsTypesAndAPIs;
using static ApolloInterop.Features.WindowsTypesAndAPIs.WinNTTypes;
using static ApolloInterop.Features.WindowsTypesAndAPIs.LSATypes;
using static ApolloInterop.Features.WindowsTypesAndAPIs.APIInteropTypes;

namespace ApolloInterop.Features.KerberosTickets;

public record struct LogonSessionData
{
    public LUID LogonId;
    public string Username;
    public string LogonDomain;
    public string AuthenticationPackage;
    public Win32.LogonType LogonType;
    public int Session;
    public SecurityIdentifier Sid;
    public DateTime LogonTime;
    public string LogonServer;
    public string DnsDomainName;
    public string Upn;
}

/// <summary>
/// Record type to represent a Kerberos ticket.
/// </summary>
public record KerberosTicket
{
    public LUID Luid { get; set; }
    public string LogonId => Luid.ToString();
    public string ClientName { get; set; }
    public string ClientRealm { get; set; }
    public string ClientFullName => $"{ClientName}@{ClientRealm}";
    public string ServerName { get; set; }
    public string ServerRealm { get; set; }
    public string ServerFullName => $"{ServerName}@{ServerRealm}";
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public DateTime RenewTime { get; set; }
    public KerbEncType EncryptionType { get; set; }
    public KerbTicketFlags TicketFlags { get; set; }
    public byte[] Kirbi { get; set; } = [];
}



public record struct KERB_QUERY_TKT_CACHE_RESPONSE
{
    public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    public uint CountOfTickets;
    public HANDLE<KERB_TICKET_CACHE_INFO_EX> Tickets;   // seems this starts at a memory address which is one IntPrt size away from the start of the struct
}

public record struct KERB_QUERY_TKT_CACHE_REQUEST
{
    public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    public LUID LogonId;
}


public record struct KERB_RETRIEVE_TKT_REQUEST
{
    public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    public LUID LogonId;
    public UNICODE_STRING TargetName;
    public uint TicketFlags;
    public KerbCacheOptions CacheOptions;
    public KERB_CRYPTO_KEY_TYPE EncryptionType;
    public SecHandle CredentialsHandle;
}



public struct KERB_RETRIEVE_TKT_RESPONSE
{
    public KERB_EXTERNAL_TICKET Ticket;
}


public struct KERB_SUBMIT_TKT_REQUEST
{
    public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    public LUID LogonId;
    public int Flags;
    public KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
    public int KerbCredSize;
    public int KerbCredOffset;
}



[StructLayout(LayoutKind.Sequential)]
public record struct KERB_PURGE_TKT_CACHE_REQUEST
{
    public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    public LUID LogonId;
    public UNICODE_STRING  ServerName;
    public UNICODE_STRING  RealmName;
}

public record struct KERB_TICKET_CACHE_INFO_EX
{
    public LSA_OUT_STRING ClientName;
    public LSA_OUT_STRING ClientRealm;
    public LSA_OUT_STRING ServerName;
    public LSA_OUT_STRING ServerRealm;
    public long StartTime;
    public long EndTime;
    public long RenewTime;
    public int EncryptionType;
    public uint TicketFlags;
}

public struct KERB_EXTERNAL_TICKET
{
    public HANDLE<KERB_EXTERNAL_NAME> ServiceName;
    public HANDLE<KERB_EXTERNAL_NAME> TargetName;
    public HANDLE<KERB_EXTERNAL_NAME> ClientName;
    public UNICODE_STRING DomainName;
    public UNICODE_STRING TargetDomainName;
    public UNICODE_STRING AltTargetDomainName;
    public KERB_CRYPTO_KEY SessionKey;
    public KerbTicketFlags TicketFlags;
    public uint Flags;
    public long KeyExpirationTime;
    public long StartTime;
    public long EndTime;
    public long RenewUntil;
    public long TimeSkew;
    public uint EncodedTicketSize;
    public HANDLE<UCHAR> EncodedTicket;
}

public struct KERB_EXTERNAL_NAME
{
    public short NameType;
    public ushort NameCount;
    public UNICODE_STRING Names;
}

public struct KERB_CRYPTO_KEY
{
    public KERB_CRYPTO_KEY_TYPE KeyType;
    public uint Length;
    public HANDLE<UCHAR> Value;
}

public struct KERB_CRYPTO_KEY32
{
    public int KeyType;
    public int Length;
    public int Offset;
}

public struct SecHandle
{
    public nuint dwLower;
    public nuint dwUpper;
}

public struct KERB_INTERACTIVE_LOGON 
{
    public KERB_LOGON_SUBMIT_TYPE LogonType;
    public UNICODE_STRING         LogonDomainName;
    public UNICODE_STRING         UserName;
    public UNICODE_STRING         Password;
}

public enum KERB_CRYPTO_KEY_TYPE
{
    KERB_ETYPE_DES_CBC_CRC = 1,
    KERB_ETYPE_DES_CBC_MD4 = 2,
    KERB_ETYPE_DES_CBC_MD5 = 3,
    KERB_ETYPE_NULL = 0,
    KERB_ETYPE_RC4_HMAC_NT = 23,
    KERB_ETYPE_RC4_MD4 = -128,
}

[Flags]
public enum KerbTicketFlags : uint
{
    Forwardable = 0x40000000,
    Forwarded = 0x20000000,
    HwAuthent = 0x00100000,
    Initial = 0x00400000,
    Invalid = 0x01000000,
    MayPostDate = 0x04000000,
    OkAsDelegate = 0x00040000,
    PostDated = 0x02000000,
    PreAuthent = 0x00200000,
    Proxiable = 0x10000000,
    Proxy = 0x08000000,
    Renewable = 0x00800000,
    Reserved = 0x80000000,
    Reserved1 = 0x00000001,
    NameCanonicalize = 0x10000
}

public enum KERB_PROTOCOL_MESSAGE_TYPE
{
    KerbDebugRequestMessage = 0,
    KerbQueryTicketCacheMessage = 1,
    KerbChangeMachinePasswordMessage = 2,
    KerbVerifyPacMessage = 3,
    KerbRetrieveTicketMessage = 4,
    KerbUpdateAddressesMessage = 5,
    KerbPurgeTicketCacheMessage = 6,
    KerbChangePasswordMessage = 7,
    KerbRetrieveEncodedTicketMessage = 8,
    KerbDecryptDataMessage = 9,
    KerbAddBindingCacheEntryMessage = 10,
    KerbSetPasswordMessage = 11,
    KerbSetPasswordExMessage = 12,
    KerbVerifyCredentialsMessage = 13,
    KerbQueryTicketCacheExMessage = 14,
    KerbPurgeTicketCacheExMessage = 15,
    KerbRefreshSmartcardCredentialsMessage = 16,
    KerbAddExtraCredentialsMessage = 17,
    KerbQuerySupplementalCredentialsMessage = 18,
    KerbTransferCredentialsMessage = 19,
    KerbQueryTicketCacheEx2Message = 20,
    KerbSubmitTicketMessage = 21,
    KerbAddExtraCredentialsExMessage = 22,
    KerbQueryKdcProxyCacheMessage = 23,
    KerbPurgeKdcProxyCacheMessage = 24,
    KerbQueryTicketCacheEx3Message = 25,
    KerbCleanupMachinePkinitCredsMessage = 26,
    KerbAddBindingCacheEntryExMessage = 27,
    KerbQueryBindingCacheMessage = 28,
    KerbPurgeBindingCacheMessage = 29,
    KerbPinKdcMessage = 30,
    KerbUnpinAllKdcsMessage = 31,
    KerbQueryDomainExtendedPoliciesMessage = 32,
    KerbQueryS4U2ProxyCacheMessage = 33,
    KerbRetrieveKeyTabMessage = 34,
    KerbRefreshPolicyMessage = 35,
    KerbPrintCloudKerberosDebugMessage = 36,
}

public enum KERB_LOGON_SUBMIT_TYPE 
{
    KerbInteractiveLogon = 2,
    KerbSmartCardLogon = 6,
    KerbWorkstationUnlockLogon = 7,
    KerbSmartCardUnlockLogon = 8,
    KerbProxyLogon = 9,
    KerbTicketLogon = 10,
    KerbTicketUnlockLogon = 11,
    KerbS4ULogon = 12,
    KerbCertificateLogon = 13,
    KerbCertificateS4ULogon = 14,
    KerbCertificateUnlockLogon = 15,
    KerbNoElevationLogon = 83,
    KerbLuidLogon = 84
}

public enum KerbEncType
{
    des_cbc_crc = 1,
    des_cbc_md4 = 2,
    des_cbc_md5 = 3,
    des3_cbc_md5 = 5,
    des3_cbc_sha1 = 7,
    dsaWithSHA1_CmsOID = 9,
    md5WithRSAEncryption_CmsOID = 10,
    sha1WithRSAEncryption_CmsOID = 11,
    rc2CBC_EnvOID = 12,
    rsaEncryption_EnvOID = 13,
    rsaES_OAEP_ENV_OID = 14,
    des_ede3_cbc_Env_OID = 15,
    des3_cbc_sha1_kd = 16,
    aes128_cts_hmac_sha1 = 17,
    aes256_cts_hmac_sha1 = 18,
    rc4_hmac = 23,
    rc4_hmac_exp = 24,
    subkey_keymaterial = 65,
    old_exp = -135
}

[Flags]
public enum KerbCacheOptions : uint
{
    KERB_RETRIEVE_TICKET_DEFAULT = 0U,
    KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 1U,
    KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 2U, 
    KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 4U,
    KERB_RETRIEVE_TICKET_AS_KERB_CRED = 8U,
    KERB_RETRIEVE_TICKET_WITH_SEC_CRED = 16U,
    KERB_RETRIEVE_TICKET_CACHE_TICKET = 32U,
    KERB_RETRIEVE_TICKET_MAX_LIFETIME = 64U
}

