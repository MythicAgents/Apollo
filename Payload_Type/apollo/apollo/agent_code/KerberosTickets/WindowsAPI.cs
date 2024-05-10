using ApolloInterop.Classes.Api;
using ApolloInterop.Features.WindowsTypesAndAPIs;
using static KerberosTickets.KerberosTicketManager;

namespace KerberosTickets;

public static class WindowsAPI
{
    public static Secur32APIs.LsaConnectUntrusted LsaConnectUntrustedDelegate { get; private set; }
    public static Secur32APIs.LsaLookupAuthenticationPackage LsaLookupAuthenticationPackageDelegate { get; private set; }
    
    public static Secur32APIs.LsaCallAuthenticationPackage LsaCallAuthenticationPackageDelegate { get; private set; }
    public static Secur32APIs.LsaEnumerateLogonSessions LsaEnumerateLogonSessionsDelegate { get; private set; }
    public static Secur32APIs.LsaFreeReturnBuffer LsaFreeReturnBufferDelegate { get; private set; }
    public static Secur32APIs.LsaRegisterLogonProcess LsaRegisterLogonProcessDelegate { get; private set; }
    public static Secur32APIs.LsaDeregisterLogonProcess LsaDeregisterLogonProcessDelegate { get; private set; }
    
    public static Secur32APIs.LsaGetLogonSessionData LsaGetLogonSessionDataDelegate { get; private set; }
    public static  Advapi32APIs.GetTokenInformation GetTokenInformationDelegate { get; private set; }
    public static NtdllAPIs.RtlMoveMemory RtlMoveMemoryDelegate { get; private set; }
    public static Advapi32APIs.LsaNtStatusToWinError LsaNtStatusToWinErrorDelegate { get; private set; }
    
    public static Kernel32APIs.OpenProcess OpenProcessDelegate { get; private set; }
    public static Advapi32APIs.OpenProcessToken OpenProcessTokenDelegate { get; private set; }
    public static Kernel32APIs.CloseHandle CloseHandleDelegate { get; private set; }
    public static Advapi32APIs.ImpersonateLoggedOnUser ImpersonateLoggedOnUserDelegate { get; private set; }
    
    public static Secur32APIs.LsaLogonUser LsaLogonUserDelegate { get; private set; }
    public static Advapi32APIs.AllocateLocallyUniqueId AllocateLocallyUniqueIdDelegate { get; private set; }
    public static Advapi32APIs.LogonUserA LogonUserADelegate { get; private set; }
    
    
    
    public static void Initialize()
    {
        LsaConnectUntrustedDelegate = Agent.GetApi().GetLibraryFunction<Secur32APIs.LsaConnectUntrusted>(Library.SECUR32, "LsaConnectUntrusted");
        LsaLookupAuthenticationPackageDelegate = Agent.GetApi().GetLibraryFunction<Secur32APIs.LsaLookupAuthenticationPackage>(Library.SECUR32, "LsaLookupAuthenticationPackage");
        LsaEnumerateLogonSessionsDelegate = Agent.GetApi().GetLibraryFunction<Secur32APIs.LsaEnumerateLogonSessions>(Library.SECUR32, "LsaEnumerateLogonSessions");
        LsaFreeReturnBufferDelegate = Agent.GetApi().GetLibraryFunction<Secur32APIs.LsaFreeReturnBuffer>(Library.SECUR32, "LsaFreeReturnBuffer");
        LsaRegisterLogonProcessDelegate = Agent.GetApi().GetLibraryFunction<Secur32APIs.LsaRegisterLogonProcess>(Library.SECUR32, "LsaRegisterLogonProcess");
        LsaDeregisterLogonProcessDelegate = Agent.GetApi().GetLibraryFunction<Secur32APIs.LsaDeregisterLogonProcess>(Library.SECUR32, "LsaDeregisterLogonProcess");
        LsaCallAuthenticationPackageDelegate = Agent.GetApi().GetLibraryFunction<Secur32APIs.LsaCallAuthenticationPackage>(Library.SECUR32, "LsaCallAuthenticationPackage");
        LsaGetLogonSessionDataDelegate = Agent.GetApi().GetLibraryFunction<Secur32APIs.LsaGetLogonSessionData>(Library.SECUR32, "LsaGetLogonSessionData");
        GetTokenInformationDelegate = Agent.GetApi().GetLibraryFunction<Advapi32APIs.GetTokenInformation>(Library.ADVAPI32, "GetTokenInformation");
        RtlMoveMemoryDelegate = Agent.GetApi().GetLibraryFunction<NtdllAPIs.RtlMoveMemory>(Library.NTDLL, "RtlMoveMemory");
        LsaNtStatusToWinErrorDelegate = Agent.GetApi().GetLibraryFunction<Advapi32APIs.LsaNtStatusToWinError>(Library.ADVAPI32, "LsaNtStatusToWinError");
        OpenProcessDelegate = Agent.GetApi().GetLibraryFunction<Kernel32APIs.OpenProcess>(Library.KERNEL32, "OpenProcess");
        OpenProcessTokenDelegate = Agent.GetApi().GetLibraryFunction<Advapi32APIs.OpenProcessToken>(Library.ADVAPI32, "OpenProcessToken");
        CloseHandleDelegate = Agent.GetApi().GetLibraryFunction<Kernel32APIs.CloseHandle>(Library.KERNEL32, "CloseHandle");
        ImpersonateLoggedOnUserDelegate = Agent.GetApi().GetLibraryFunction<Advapi32APIs.ImpersonateLoggedOnUser>(Library.ADVAPI32, "ImpersonateLoggedOnUser");
        LsaLogonUserDelegate = Agent.GetApi().GetLibraryFunction<Secur32APIs.LsaLogonUser>(Library.SECUR32, "LsaLogonUser");
        AllocateLocallyUniqueIdDelegate = Agent.GetApi().GetLibraryFunction<Advapi32APIs.AllocateLocallyUniqueId>(Library.ADVAPI32, "AllocateLocallyUniqueId");
        LogonUserADelegate = Agent.GetApi().GetLibraryFunction<Advapi32APIs.LogonUserA>(Library.ADVAPI32, "LogonUserA");
    }
    
}