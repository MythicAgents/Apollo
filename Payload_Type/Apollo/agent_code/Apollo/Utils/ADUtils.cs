using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using Apollo.Utils;
using AD = System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.ActiveDirectory;
using System.Net;

namespace Utils
{
    public static class ADUtils
    {
        public struct NetLocalGroupMember
        {
            public string ComputerName;
            public string GroupName;
            public string MemberName;
            public string SID;
            public bool IsGroup;
        }

        public struct NetLocalGroup
        {
            public string ComputerName;
            public string GroupName;
            public string Comment;
            public string SID;
        }

        public struct NetDomainController
        {
            public string ComputerName;
            public string IPAddress;
            public string Domain;
            public string Forest;
            public string OSVersion;
            public bool IsGlobalCatalog;
        }

        //Example code for a class file or dll( I used a dll)
        public static NetLocalGroupMember[] GetLocalGroupMembers(string serverName, string groupName)
        {
            List<NetLocalGroupMember> results = new List<NetLocalGroupMember>();
            int entriesRead;
            int totalEntries;
            IntPtr resumePtr = IntPtr.Zero;
            int val = Native.Methods.NetLocalGroupGetMembers(serverName, groupName, 2, out IntPtr bufPtr, -1, out entriesRead, out totalEntries, ref resumePtr);
            if (entriesRead > 0)
            {
                Native.Structures.LOCALGROUP_MEMBERS_INFO_2[] groupMembers = new Native.Structures.LOCALGROUP_MEMBERS_INFO_2[entriesRead];
                IntPtr iter = bufPtr;
                for (int i = 0; i < entriesRead; i++)
                {
                    groupMembers[i] = (Native.Structures.LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(iter, typeof(Native.Structures.LOCALGROUP_MEMBERS_INFO_2));
                    iter = (IntPtr)((int)iter + Marshal.SizeOf(typeof(Native.Structures.LOCALGROUP_MEMBERS_INFO_2)));
                    //myList.Add(Marshal.PtrToStringUni(Members[i].lgrmi2_domainandname) + "," + Members[i].lgrmi2_sidusage);
                    string sidString = "";
                    bool bRet = Native.Methods.ConvertSidToStringSid(groupMembers[i].lgrmi2_sid, out sidString);
                    if (!bRet)
                        continue;
                    var result = new NetLocalGroupMember();
                    result.ComputerName = serverName;
                    result.GroupName = groupName;
                    result.IsGroup = (groupMembers[i].lgrmi2_sidusage == Native.Enums.SID_NAME_USE.SidTypeGroup);
                    result.SID = sidString;
                    result.MemberName = Marshal.PtrToStringUni(groupMembers[i].lgrmi2_domainandname);
                    results.Add(result);
                }
                Native.Methods.NetApiBufferFree(bufPtr);
            }
            return results.ToArray();
        }

        internal static NetLocalGroup[] GetLocalGroups(string serverName)
        {
            int res = 0;
            int level = 1;
            IntPtr buffer = IntPtr.Zero;
            int MAX_PREFERRED_LENGTH = -1;
            int read, total;
            IntPtr handle = IntPtr.Zero;
            List<NetLocalGroup> results = new List<NetLocalGroup>();

            var groups = new List<Native.Structures.LOCALGROUP_USERS_INFO_1>();
            try
            {
                res = Native.Methods.NetLocalGroupEnum(serverName, level, out buffer, MAX_PREFERRED_LENGTH,
                    out read, out total, ref handle);

                if (res != (int)Native.Enums.NET_API_STATUS.NERR_Success)
                {
                    DumpError(res);
                    return results.ToArray();
                }

                IntPtr ptr = buffer;
                for (int i = 0; i < read; i++)
                {
                    var group = (Native.Structures.LOCALGROUP_USERS_INFO_1)Marshal.PtrToStructure(ptr, typeof(Native.Structures.LOCALGROUP_USERS_INFO_1));
                    var result = new NetLocalGroup();
                    result.ComputerName = serverName;
                    result.GroupName = Marshal.PtrToStringUni(group.name);
                    result.Comment = Marshal.PtrToStringUni(group.comment);
                    results.Add(result);
                    ptr = (IntPtr)((int)ptr + Marshal.SizeOf(typeof(Native.Structures.LOCALGROUP_USERS_INFO_1)));
                }
            }
            finally
            {
                Native.Methods.NetApiBufferFree(buffer);
            }

            return results.ToArray();
        }

        internal static NetDomainController[] FindAllDomainControllers(string domain)
        {
            DirectoryContext ctx;
            AD.DomainControllerCollection dcCollection;
            List<NetDomainController> results = new List<NetDomainController>();
            if (string.IsNullOrEmpty(domain))
                ctx = new DirectoryContext(DirectoryContextType.Domain);
            else
                ctx = new DirectoryContext(DirectoryContextType.Domain, domain);
            dcCollection = DomainController.FindAll(ctx);
            foreach (DomainController dc in dcCollection)
            {
                var result = new NetDomainController();
                result.ComputerName = dc.Name;
                result.Domain = dc.Domain.ToString();
                try
                {
                    var ips = Dns.GetHostAddresses(result.ComputerName);
                    string ipList = "";
                    for (int i = 0; i < ips.Length; i++)
                    {
                        if (i == ips.Length - 1)
                            ipList += $"{ips[i].ToString()}";
                        else
                            ipList += $"{ips[i].ToString()}, ";
                    }
                    result.IPAddress = ipList;
                } catch (Exception ex)
                {
                    result.IPAddress = dc.IPAddress;
                }
                result.Forest = dc.Forest.ToString();
                result.OSVersion = dc.OSVersion;
                result.IsGlobalCatalog = dc.IsGlobalCatalog();
                results.Add(result);
            }
            return results.ToArray();
        }

        private static void DumpError(int res)
        {
            if (res == Native.Win32Error.ERROR_ACCESS_DENIED)
                DebugUtils.DebugWriteLine("ERROR_ACCESS_DENIED");
            else if (res == Native.Win32Error.ERROR_MORE_DATA)
                DebugUtils.DebugWriteLine("ERROR_MORE_DATA");
            else if (res == Native.Win32Error.NERR_InvalidComputer)
                DebugUtils.DebugWriteLine("NERR_InvalidComputer");
            else if (res == Native.Win32Error.NERR_BufTooSmall)
                DebugUtils.DebugWriteLine("NERR_BufTooSmall");
            else
                DebugUtils.DebugWriteLine("Error 0x" + res.ToString("x"));
        }

    }
}
