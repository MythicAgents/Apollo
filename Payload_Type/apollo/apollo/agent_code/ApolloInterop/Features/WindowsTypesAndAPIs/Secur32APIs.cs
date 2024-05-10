using ApolloInterop.Enums;
using static ApolloInterop.Features.WindowsTypesAndAPIs.APIInteropTypes;


namespace ApolloInterop.Features.WindowsTypesAndAPIs;

public static class Secur32APIs
{
    public delegate NTSTATUS LsaConnectUntrusted(out HANDLE lsaHandle);
    public delegate NTSTATUS LsaLookupAuthenticationPackage(HANDLE lsaHandle, HANDLE packageName, out  uint authPackage);
    public delegate NTSTATUS LsaCallAuthenticationPackage(HANDLE lsaHandle, uint authPackage, HANDLE submitBuffer, int submitBufferLength, out HANDLE returnBuffer, out uint returnBufferLength, out NTSTATUS authPackageStatus);
    //the SecurityMode argument is discarded following the documentation specifying it should be ignored
    public delegate NTSTATUS LsaRegisterLogonProcess(HANDLE logonProcessName, HANDLE lsaHandle, HANDLE _);
    public delegate NTSTATUS LsaDeregisterLogonProcess(HANDLE lsaHandle);
    public delegate NTSTATUS LsaEnumerateLogonSessions(out uint logonSessionCount, out HANDLE logonSessionList);
    public delegate NTSTATUS LsaFreeReturnBuffer(HANDLE buffer);
    public delegate NTSTATUS LsaGetLogonSessionData(HANDLE LogonIdHandle, out HANDLE LogonSessionDataHandle);
    public delegate NTSTATUS LsaLogonUser(HANDLE lsaHandle, LSATypes.LSA_IN_STRING originName, Win32.LogonType logonType, uint authPackage, HANDLE submitBuffer, uint submitBufferLength, HANDLE localgroups, WinNTTypes.TOKEN_SOURCE sourceContext, out HANDLE profileBuffer, out uint profileBufferLength, out WinNTTypes.LUID logonId, out HANDLE token, out LSATypes.QUOTA_LIMITS quotas, out NTSTATUS subStatus);
    
}