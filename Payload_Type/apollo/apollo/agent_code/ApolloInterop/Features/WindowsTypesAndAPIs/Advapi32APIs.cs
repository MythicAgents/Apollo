using System.Security.Principal;
using ApolloInterop.Enums;
using static ApolloInterop.Features.WindowsTypesAndAPIs.WinNTTypes;
using static ApolloInterop.Features.WindowsTypesAndAPIs.LSATypes;
using static ApolloInterop.Features.WindowsTypesAndAPIs.APIInteropTypes;
namespace ApolloInterop.Features.WindowsTypesAndAPIs;

public class Advapi32APIs
{
    public delegate NTSTATUS LsaOpenPolicy(HANDLE<LSA_OUT_STRING> SystemName, HANDLE<OBJECT_ATTRIBUTES> ObjectAttributes, ACCESS_MASK DesiredAccess, out HANDLE PolicyHandle);
    public delegate bool GetTokenInformation( HANDLE tokenHandle, Win32.TokenInformationClass tokenInformationClass, HANDLE tokenInformation, int tokenInformationLength, out int returnLength);
    public delegate uint LsaNtStatusToWinError(NTSTATUS status);
    public delegate bool OpenProcessToken(HANDLE ProcessHandle, TokenAccessLevels DesiredAccess, out HANDLE TokenHandle);
    public delegate bool ImpersonateLoggedOnUser(HANDLE TokenHandle);
    public delegate bool AllocateLocallyUniqueId(out LUID luid);
    public delegate bool LogonUserA(HANDLE lpszUsername, HANDLE lpszDomain, HANDLE lpszPassword, Win32.LogonType dwLogonType, Win32.LogonProvider dwLogonProvider, out HANDLE phToken);
}